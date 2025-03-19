use async_std::fs;
use async_std::future::timeout;
use async_std::io::WriteExt;
use async_std::net::TcpStream;
use async_std::path::Path;
use async_std::task;
use async_std::task::JoinHandle;
use dsa::signature::{Signer, Verifier};
use libp2p::core::{ProtocolName, UpgradeInfo};
use libp2p::futures::future::BoxFuture;
use libp2p::futures::{AsyncRead, AsyncReadExt, AsyncWrite, FutureExt};
use libp2p::swarm::NegotiatedSubstream;
use libp2p::{InboundUpgrade, OutboundUpgrade};
use log::{debug, error, info};
use ssh_key::{Algorithm, HashAlg, PrivateKey, PublicKey};
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

pub type PendingConnection = JoinHandle<Result<(), io::Error>>;

pub struct ProxyClientProtocol {
    pub(crate) private_key: PrivateKey,
    pub(crate) socket_addr: SocketAddr,
    pub(crate) stream: TcpStream,
}

pub struct ProxyServerProtocol {
    pub public_key: PublicKey,
}

#[derive(Debug, Copy, Clone)]
pub enum ProxyVersion {
    Version1, // 1.0.0
}

impl ProtocolName for ProxyVersion {
    fn protocol_name(&self) -> &[u8] {
        match self {
            ProxyVersion::Version1 => b"/gnostr/proxy/1.0.0",
        }
    }
}

pub const SUPPORTED_VERSIONS: [ProxyVersion; 1] = [ProxyVersion::Version1];

const OK_BYTE: &[u8] = b"\x01";
const ERR_BYTE: &[u8] = b"\x00"; // maybe in future add more verbose errors
const MAX_ADDR_LEN: usize = 1024;

impl ProtocolName for ProxyClientProtocol {
    fn protocol_name(&self) -> &[u8] {
        ProxyVersion::Version1.protocol_name()
    }
}

impl ProtocolName for ProxyServerProtocol {
    fn protocol_name(&self) -> &[u8] {
        ProxyVersion::Version1.protocol_name()
    }
}

impl UpgradeInfo for ProxyClientProtocol {
    type Info = &'static [u8];
    type InfoIter = Vec<&'static [u8]>;

    fn protocol_info(&self) -> Self::InfoIter {
        SUPPORTED_VERSIONS
            .iter()
            .map(|v| v.protocol_name())
            .collect()
    }
}

impl UpgradeInfo for ProxyServerProtocol {
    type Info = &'static [u8];
    type InfoIter = Vec<&'static [u8]>;

    fn protocol_info(&self) -> Self::InfoIter {
        SUPPORTED_VERSIONS
            .iter()
            .map(|v| v.protocol_name())
            .collect()
    }
}

impl InboundUpgrade<NegotiatedSubstream> for ProxyServerProtocol {
    type Output = PendingConnection;
    type Error = io::Error;
    type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

    fn upgrade_inbound(self, mut socket: NegotiatedSubstream, _: Self::Info) -> Self::Future {
        async move {
            let ProxyServerProtocol { public_key } = self;

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
        }
        .boxed()
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
                stream,
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
        }
        .boxed()
    }
}

async fn read_u64<I>(mut stream: I) -> io::Result<u64>
where
    I: AsyncRead + Unpin,
{
    let mut u64_buf = [0 as u8; 8];

    stream.read_exact(&mut u64_buf).await?;
    Ok(u64::from_le_bytes(u64_buf))
}

async fn read_len<I>(mut stream: I, len: usize) -> io::Result<Vec<u8>>
where
    I: AsyncRead + Unpin,
{
    let mut buf: [u8; MAX_ADDR_LEN] = [0; MAX_ADDR_LEN];

    if len > MAX_ADDR_LEN {
        return Err(io::ErrorKind::InvalidData.into());
    }

    let read = stream.read_exact(&mut buf[0..len]);
    let res = timeout(Duration::from_millis(100), read).await;

    if res.is_err() {
        return Err(io::ErrorKind::TimedOut.into());
    }
    res.unwrap()?;

    Ok(Vec::from(&buf[0..len]))
}

async fn read_address<I>(mut stream: I, key: PublicKey) -> io::Result<SocketAddr>
where
    I: AsyncRead + Unpin,
{
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
                return Err(io::ErrorKind::InvalidData.into());
            }
            match SocketAddr::from_str(res.unwrap()) {
                Ok(addr) => Ok(addr),
                Err(_) => Err(io::ErrorKind::InvalidData.into()),
            }
        }
        Err(err) => {
            error!("Cannot verify signature: {err}");
            Err(io::ErrorKind::InvalidData.into())
        }
    }
}

async fn write_address<I>(mut stream: I, key: PrivateKey, addr: SocketAddr) -> io::Result<()>
where
    I: AsyncWrite + Unpin,
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
    let t1 = async move { async_std::io::copy(&mut stream_reader1, &mut stream_writer2).await };

    let t2 = async move { async_std::io::copy(&mut stream_reader2, &mut stream_writer1).await };

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

#[cfg(test)]
mod test {
    use crate::protocol::{read_address, write_address, ProxyClientProtocol};
    use async_std::fs;
    use async_std::future::timeout;
    use async_std::io::WriteExt;
    use async_std::net::TcpStream;
    use async_std::path::Path;
    use async_std::stream::Stream;
    use futures::AsyncReadExt;
    use libp2p::futures::{AsyncRead, AsyncWrite, FutureExt};
    use ssh_key::{Algorithm, PrivateKey, PublicKey};
    use std::error::Error;
    use std::io::{self, Cursor, Read, Write};
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::str::FromStr;
    use std::task::{Context, Poll};

    #[derive(Default, Debug)]
    pub struct MockStream {
        buf: Cursor<Vec<u8>>,
        from_index: usize,
    }

    impl Unpin for MockStream {}

    impl MockStream {
        pub fn from(buf: &[u8]) -> Self {
            Self {
                buf: Cursor::new(Vec::from(buf)),
                from_index: 0,
            }
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let this: &mut Self = Pin::into_inner(self);
            this.buf.set_position(this.from_index.clone() as u64);
            let res = this.buf.read(buf);
            if let Ok(s) = res {
                this.from_index += s;
            }
            Poll::Ready(res)
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this: &mut Self = Pin::into_inner(self);
            Poll::Ready(this.buf.write(buf))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Stream for MockStream {
        type Item = Result<Vec<u8>, io::Error>;
        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            let this: &mut Self = Pin::into_inner(self);
            let mut buf = [0u8; 1024];
            match Pin::new(this).poll_read(cx, &mut buf) {
                Poll::Pending => Poll::Ready(None),
                Poll::Ready(Ok(b)) if b == 0 => Poll::Ready(None),
                Poll::Ready(Ok(b)) => Poll::Ready(Some(Ok(Vec::from(&buf[..b])))),
                Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e))),
            }
        }
    }

    impl AsRef<[u8]> for MockStream {
        fn as_ref(&self) -> &[u8] {
            self.buf.get_ref()
        }
    }

    #[async_std::test]
    async fn test_handshake() -> Result<(), Box<dyn Error>> {
        let a = SocketAddr::from_str("127.0.0.1:8080")?;
        let (r, w) = MockStream::from(b"").split();


        // WARNING: don't actually hardcode private keys in source code!!!
        let encoded_key = r#"
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----
"#;

        let private_key = PrivateKey::from_openssh(encoded_key)?;

        // Key attributes
        assert_eq!(private_key.algorithm(), ssh_key::Algorithm::Ed25519);
        assert_eq!(private_key.comment(), "user@example.com");

        // Key data: in this example an Ed25519 key
        if let Some(ed25519_keypair) = private_key.key_data().ed25519() {
            assert_eq!(
                ed25519_keypair.public.as_ref(),
                [
                    0xb3, 0x3e, 0xae, 0xf3, 0x7e, 0xa2, 0xdf, 0x7c, 0xaa, 0x1, 0xd, 0xef, 0xde,
                    0xa3, 0x4e, 0x24, 0x1f, 0x65, 0xf1, 0xb5, 0x29, 0xa4, 0xf4, 0x3e, 0xd1, 0x43,
                    0x27, 0xf5, 0xc5, 0x4a, 0xab, 0x62
                ]
                .as_ref()
            );
            assert_eq!(
                ed25519_keypair.private.as_ref(),
                [
                    0xb6, 0x6, 0xc2, 0x22, 0xd1, 0xc, 0x16, 0xda, 0xe1, 0x6c, 0x70, 0xa4, 0xd4,
                    0x51, 0x73, 0x47, 0x2e, 0xc6, 0x17, 0xe0, 0x5c, 0x65, 0x69, 0x20, 0xd2, 0x6e,
                    0x56, 0xc0, 0x8f, 0xb5, 0x91, 0xed
                ]
                .as_ref()
            );

            let public_key = ed25519_keypair.public;
            write_address(w, private_key, a).await?;
            let addr = read_address(r, public_key.into()).await?;
            assert_eq!(addr, a);
        }

        Ok(())
    }
}
