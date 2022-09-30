use std::io;
use std::net::{SocketAddr};
use std::str::FromStr;
use std::time::Duration;
use async_std::future::timeout;
use async_std::io::WriteExt;
use dsa::signature::{Signer, Verifier};
use libp2p::core::{ProtocolName, UpgradeInfo};
use libp2p::{InboundUpgrade, OutboundUpgrade};
use libp2p::futures::future::{BoxFuture};
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, FutureExt};
use libp2p::swarm::{NegotiatedSubstream};
use ssh_key::{PrivateKey, PublicKey};
use async_std::net::{TcpStream};
use log::{debug, error, info};
use async_std::task;
use async_std::task::JoinHandle;

pub type PendingConnection = JoinHandle<Result<(), io::Error>>;

pub struct ProxyClientProtocol {
    pub(crate) private_key: PrivateKey,
    pub(crate) socket_addr: SocketAddr,
    pub(crate) stream: TcpStream
}

pub struct ProxyServerProtocol {
    pub public_key: PublicKey,
}

#[derive(Debug, Copy, Clone)]
pub enum ProxyVersion {
    Version1 // 1.0.0
}

impl ProxyVersion {
    fn client(&self) -> &[u8] {
        match self {
            ProxyVersion::Version1 => CLIENT_V1_VER
        }
    }

    fn server(&self) -> &[u8] {
        match self {
            ProxyVersion::Version1 => SERVER_V1_VER
        }
    }
}

pub const CLIENT_V1_VER: &[u8] = b"/tricker/proxy/1.0.0/client";
pub const SERVER_V1_VER: &[u8] = b"/tricker/proxy/1.0.0/server";

pub const SUPPORTED_VERSIONS: [ProxyVersion; 1] = [ProxyVersion::Version1];

const OK_BYTE: &[u8] = b"\x01";
const ERR_BYTE: &[u8] = b"\x00";  // maybe in future add more verbose errors
const MAX_ADDR_LEN: usize = 128;

impl ProtocolName for ProxyClientProtocol {
    fn protocol_name(&self) -> &[u8] {
        ProxyVersion::Version1.client()
    }
}

impl ProtocolName for ProxyServerProtocol {
    fn protocol_name(&self) -> &[u8] {
        ProxyVersion::Version1.server()
    }
}

impl UpgradeInfo for ProxyClientProtocol {
    type Info = &'static [u8];
    type InfoIter = Vec<&'static [u8]>;

    fn protocol_info(&self) -> Self::InfoIter {
        SUPPORTED_VERSIONS.iter()
            .map(|v| v.client())
            .collect()

    }
}

impl UpgradeInfo for ProxyServerProtocol {
    type Info = &'static [u8];
    type InfoIter = Vec<&'static [u8]>;

    fn protocol_info(&self) -> Self::InfoIter {
        SUPPORTED_VERSIONS.iter()
            .map(|v| v.client())
            .collect()

    }
}

impl InboundUpgrade<NegotiatedSubstream> for ProxyServerProtocol {
    type Output = PendingConnection;
    type Error = io::Error;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, mut socket: NegotiatedSubstream, _: Self::Info) -> Self::Future {
        async move {

            let ProxyServerProtocol {public_key, } = self;

            let res = read_address(&mut socket, public_key).await;

            if let Err(err) = res {
                error!("Cannot read address from stream: {}", err);
                let _ = &socket.write(ERR_BYTE).await?;
                return Err(err);
            }

            let addr = res.unwrap();
            let stream = TcpStream::connect(addr).await?;

            let _ = &socket.write(OK_BYTE).await?;

            info!("Connecting inbound stream to address {addr}");
            let conn = task::spawn(connect(stream, socket));


            return Ok(conn);

        }.boxed()
    }
}

impl OutboundUpgrade<NegotiatedSubstream> for ProxyClientProtocol {
    type Output = PendingConnection;
    type Error = io::Error;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_outbound(self, socket: NegotiatedSubstream, _: Self::Info) -> Self::Future {
        async move {

            let mut socket = socket;

            let ProxyClientProtocol {
                private_key,
                socket_addr,
                stream
            } = self;

            write_address(&mut socket, private_key, socket_addr).await?;

            let mut buf = [0 as u8; 1];

            let resp = timeout(Duration::from_secs(10), (&mut socket).read_exact(&mut buf)).await;

            if resp.is_err() || resp.unwrap().is_err() || buf != OK_BYTE {
                return Err(io::ErrorKind::Other.into());
            }
            
            debug!("Stream connected to address {socket_addr}");

            let conn = task::spawn(connect(stream, socket));
            Ok(conn)
        }.boxed()
    }
}

async fn read_u64<I> (mut stream: I) -> io::Result<u64>
    where I: AsyncRead + Unpin {

    let mut u64_buf = [0 as u8; 8];

    stream.read_exact(&mut u64_buf).await?;
    Ok(u64::from_le_bytes(u64_buf))
}

async fn read_len<I> (mut stream: I, len: usize) -> io::Result<Vec<u8>>
    where I: AsyncRead + Unpin {

    let mut buf: [u8; MAX_ADDR_LEN] = [0; MAX_ADDR_LEN];

    if len > MAX_ADDR_LEN {
        return Err(io::ErrorKind::InvalidData.into());
    }

    let read = stream.read_exact(&mut buf[0 .. len]);
    let res = timeout(Duration::from_millis(100), read).await;

    if res.is_err() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    res.unwrap()?;

    Ok(Vec::from(&buf[0 .. len]))
}

async fn read_address<I>(mut stream: I, key: PublicKey) -> io::Result<SocketAddr>
    where I: AsyncRead + Unpin {

    let addr_len = read_u64(&mut stream).await?;
    let addr_bytes = read_len(&mut stream, addr_len as usize).await?;

    let sign_len = read_u64(&mut stream).await?;
    let sign_bytes = read_len(&mut stream, sign_len as usize).await?;

    let sign = ssh_key::Signature::new(key.algorithm(), sign_bytes);
    if !sign.is_ok() {
        error!("Signature creation failed: {}", sign.unwrap_err());
        return Err(io::ErrorKind::InvalidData.into());
    }

    let res = key.verify(&addr_bytes, &sign.unwrap());

    match res {
        Ok(_) => {
            let res = std::str::from_utf8(&addr_bytes);
            if res.is_err() {
                return Err(io::ErrorKind::InvalidData.into())
            }
            match SocketAddr::from_str(res.unwrap()) {
                Ok(addr) => Ok(addr),
                Err(_) => Err(io::ErrorKind::InvalidData.into())
            }
        }
        Err(_) => Err(io::ErrorKind::InvalidData.into())
    }
}

async fn write_address<I>(mut stream: I, key: PrivateKey, addr: SocketAddr) -> io::Result<()>
    where I: AsyncWrite + Unpin
{
    let addr = addr.to_string();
    let addr_bytes = addr.as_bytes();
    let sign = key.sign(addr_bytes);
    let sign_bytes = sign.as_bytes();

    let addr_len = addr_bytes.len() as u64;
    let sign_len = sign_bytes.len() as u64;

    stream.write_all(&addr_len.to_le_bytes()).await?;
    stream.write_all(addr_bytes).await?;

    stream.write_all(&sign_len.to_le_bytes()).await?;
    stream.write_all(sign_bytes).await?;
    Ok(())
}


pub async fn connect<I, O>(stream1: I, stream2: O) -> io::Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    let (mut stream_reader1, mut stream_writer1) = stream1.split();
    let (mut stream_reader2, mut stream_writer2) = stream2.split();


    // move vars to destroy them
    let t1 = async move {
        async_std::io::copy(&mut stream_reader1, &mut stream_writer2).await
    };

    let t2 = async move {
        async_std::io::copy(&mut stream_reader2, &mut stream_writer1).await
    };

    let (r1, r2) = futures::join!(t1, t2);

    if let Err(err) = r1 {
        error!("Error while communicating: {err}");
        return Err(err);
    }

    if let Err(err) = r2 {
        error!("Error while communicating: {err}");
        return Err(err);
    }

    debug!("Connection completed successfully");

    Ok(())
}