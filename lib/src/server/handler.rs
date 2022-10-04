use std::io;
use std::task::{Context, Poll};
use libp2p::core::upgrade::DeniedUpgrade;
use libp2p::futures::FutureExt;
use libp2p::swarm::{ConnectionHandler, ConnectionHandlerEvent, ConnectionHandlerUpgrErr, KeepAlive, SubstreamProtocol};
use libp2p::swarm::handler::{InboundUpgradeSend, OutboundUpgradeSend};
use ssh_key::PublicKey;
use void::Void;
use crate::protocol::{PendingConnection, ProxyServerProtocol};

pub struct ProxyServerHandler {
    key: PublicKey,
    pending_connections: Vec<PendingConnection>
}

impl ProxyServerHandler {
    pub fn new(key: PublicKey) -> Self {
        ProxyServerHandler{
            key, pending_connections: Vec::new()
        }
    }
}

impl ConnectionHandler for ProxyServerHandler {
    type InEvent = ();
    type OutEvent = ();
    type Error = io::Error;
    type InboundProtocol = ProxyServerProtocol;
    type OutboundProtocol = DeniedUpgrade;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        SubstreamProtocol::new(
            ProxyServerProtocol {
                public_key: self.key.clone()
            }, ()
        )
    }

    fn inject_fully_negotiated_inbound(&mut self, con: PendingConnection, _: ()) {
        self.pending_connections.push(con);
    }

    fn inject_fully_negotiated_outbound(&mut self, _: Void, _: ()) {}

    fn inject_event(&mut self, _: ()) {}

    fn inject_dial_upgrade_error(&mut self, _: (), _: ConnectionHandlerUpgrErr<Void>) {}

    fn connection_keep_alive(&self) -> KeepAlive {
        KeepAlive::Yes
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<ConnectionHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::OutEvent, Self::Error>> {
        let mut new_con = Vec::new();

        while let Some(mut con) = self.pending_connections.pop() {
            if let Poll::Pending = con.poll_unpin(cx) {
                new_con.push(con);
            }
        }
        self.pending_connections = new_con;
        Poll::Pending
    }
}