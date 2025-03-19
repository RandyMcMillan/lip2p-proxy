use crate::client::ProxyOutClientEvent::Stopped;
use crate::protocol::{PendingConnection, ProxyClientProtocol};
use async_std::net::TcpStream;
use libp2p::core::upgrade::DeniedUpgrade;
use libp2p::core::{ProtocolName, UpgradeError, UpgradeInfo};
use libp2p::futures::{FutureExt, Sink};
use libp2p::swarm::handler::{InboundUpgradeSend, OutboundUpgradeSend};
use libp2p::swarm::{
    ConnectionHandler, ConnectionHandlerEvent, ConnectionHandlerUpgrErr, KeepAlive,
    SubstreamProtocol,
};
use log::{debug, error};
use ssh_key::PrivateKey;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::io::Error;
use std::net::SocketAddr;
use std::ops::Add;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use void::Void;

#[derive(Debug)]
pub enum ProxyInClientEvent {
    Connect { addr: SocketAddr, stream: TcpStream },
    Disconnect(SocketAddr),
    DisconnectAll,
    Stop,
}

#[derive(Debug)]
pub enum ProxyOutClientEvent {
    Connected(SocketAddr),
    Disconnected(SocketAddr),
    CommunicationCompleted(SocketAddr),
    Error(SocketAddr, Error),
    Stopped,
}

pub struct ProxyClientHandler {
    pub(crate) key: PrivateKey,
    pending_events: VecDeque<ProxyInClientEvent>,
    pending_out_events: VecDeque<ProxyOutClientEvent>,
    pending_connections: HashMap<SocketAddr, PendingConnection>,
    stopped: bool,
}

fn conn_error_to_io(err: ConnectionHandlerUpgrErr<Error>) -> Error {
    match err {
        ConnectionHandlerUpgrErr::Timeout => io::ErrorKind::TimedOut.into(),
        ConnectionHandlerUpgrErr::Timer => io::ErrorKind::Other.into(),
        ConnectionHandlerUpgrErr::Upgrade(err) => match err {
            UpgradeError::Select(err) => err.into(),
            UpgradeError::Apply(err) => err,
        },
    }
}

impl ProxyClientHandler {
    pub fn new(key: PrivateKey) -> Self {
        ProxyClientHandler {
            key,
            pending_events: VecDeque::new(),
            pending_connections: HashMap::new(),
            pending_out_events: VecDeque::new(),
            stopped: false,
        }
    }
}

impl ConnectionHandler for ProxyClientHandler {
    type InEvent = ProxyInClientEvent;
    type OutEvent = ProxyOutClientEvent;
    type Error = io::Error;
    type InboundProtocol = DeniedUpgrade;
    type OutboundProtocol = ProxyClientProtocol;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = SocketAddr;

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(DeniedUpgrade {}, ())
    }

    fn inject_fully_negotiated_inbound(&mut self, _: Void, _: ()) {}

    fn inject_fully_negotiated_outbound(&mut self, conn: PendingConnection, addr: SocketAddr) {
        self.pending_connections.insert(addr, conn);
        self.pending_out_events
            .push_back(ProxyOutClientEvent::Connected(addr));
    }

    fn inject_event(&mut self, event: Self::InEvent) {
        self.pending_events.push_back(event);
    }

    fn inject_dial_upgrade_error(
        &mut self,
        info: Self::OutboundOpenInfo,
        error: ConnectionHandlerUpgrErr<<Self::OutboundProtocol as OutboundUpgradeSend>::Error>,
    ) {
        error!("Error while connecting to server to addr {info}: {error}");
        self.pending_out_events
            .push_back(ProxyOutClientEvent::Error(info, conn_error_to_io(error)));
    }

    fn connection_keep_alive(&self) -> KeepAlive {
        KeepAlive::Yes
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<
        ConnectionHandlerEvent<
            Self::OutboundProtocol,
            Self::OutboundOpenInfo,
            Self::OutEvent,
            Self::Error,
        >,
    > {
        if self.stopped {
            return Poll::Pending;
        }

        while let Some(event) = self.pending_events.pop_front() {
            match event {
                ProxyInClientEvent::Connect { addr, stream } => {
                    let proto = ProxyClientProtocol {
                        private_key: self.key.clone(),
                        socket_addr: addr,
                        stream,
                    };

                    debug!(
                        "Initing protocol {:?}, supports {:?}",
                        proto.protocol_name(),
                        proto.protocol_info()
                    );

                    return Poll::Ready(ConnectionHandlerEvent::OutboundSubstreamRequest {
                        protocol: SubstreamProtocol::new(proto, addr),
                    });
                }
                ProxyInClientEvent::Disconnect(addr) => {
                    let con = self.pending_connections.remove(&addr);
                    if let Some(con) = con {
                        drop(con);
                        self.pending_connections.remove(&addr);
                    }
                }
                ProxyInClientEvent::DisconnectAll => {
                    self.pending_connections.clear();
                }
                ProxyInClientEvent::Stop => {
                    // Clear all connections and send stopped event
                    self.pending_connections.clear();
                    self.stopped = true;

                    return Poll::Ready(ConnectionHandlerEvent::Custom(Stopped));
                }
            }
        }

        if let Some(ev) = self.pending_out_events.pop_front() {
            return Poll::Ready(ConnectionHandlerEvent::Custom(ev));
        }

        let mut to_remove = Vec::new();

        for (addr, mut con) in self.pending_connections.iter_mut() {
            if let Poll::Ready(res) = con.poll_unpin(cx) {
                match res {
                    Ok(res) => {}
                    Err(err) => {
                        error!("Error while connection {err}");
                        self.pending_out_events
                            .push_back(ProxyOutClientEvent::Error(
                                addr.clone(),
                                io::ErrorKind::Other.into(),
                            ))
                    }
                }
                to_remove.push(addr.clone());
            }
        }

        for addr in to_remove {
            self.pending_connections.remove(&addr);
        }

        Poll::Pending
    }
}
