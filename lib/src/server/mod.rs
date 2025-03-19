mod handler;

use handler::ProxyServerHandler;
use libp2p::core::connection::ConnectionId;
use libp2p::swarm::{
    ConnectionHandler, IntoConnectionHandler, NetworkBehaviour, NetworkBehaviourAction,
    PollParameters,
};
use libp2p::PeerId;
use ssh_key::PublicKey;
use std::task::{Context, Poll};

pub struct ProxyServer {
    pub(crate) key: PublicKey,
}

impl ProxyServer {
    pub fn new(key: PublicKey) -> Self {
        ProxyServer { key }
    }
}

impl NetworkBehaviour for ProxyServer {
    type ConnectionHandler = ProxyServerHandler;
    type OutEvent = ();

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        ProxyServerHandler::new(self.key.clone())
    }

    fn inject_event(
        &mut self,
        peer_id: PeerId,
        connection: ConnectionId,
        event: <<Self::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::OutEvent,
    ) {
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        Poll::Pending
    }
}
