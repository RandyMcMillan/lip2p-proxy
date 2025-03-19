use crate::{Multiaddr, SwarmEvent, BOOTNODES};
use async_std::task::block_on;
use futures::StreamExt;
use libp2p::core::transport::{upgrade, OrTransport};
use libp2p::identify::{Identify, IdentifyConfig, IdentifyEvent};
use libp2p::kad::store::MemoryStore;
use libp2p::kad::{
    BootstrapError, BootstrapResult, GetClosestPeersError, Kademlia, KademliaConfig, KademliaEvent,
    QueryResult,
};
use libp2p::swarm::dial_opts::DialOpts;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{
    development_transport, identity, noise, relay, NetworkBehaviour, PeerId, Swarm, Transport,
};
use libp2p_dns::DnsConfig;
use libp2p_proxy::client::{ProxyClient, ProxyClientEvent};
use libp2p_tcp::{GenTcpConfig, TcpTransport};
use log::{debug, info};
use ssh_key::PrivateKey;
use std::borrow::BorrowMut;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "ClientEvent")]
struct ClientBehaviour {
    kadmelia: Kademlia<MemoryStore>,
    client: ProxyClient,
    ident: Identify,
    relay: relay::v2::client::Client,
}

#[derive(Debug)]
enum ClientEvent {
    Client(ProxyClientEvent),
    Kadmelia(KademliaEvent),
    Ident(IdentifyEvent),
    Relay(relay::v2::client::Event),
}

impl From<KademliaEvent> for ClientEvent {
    fn from(e: KademliaEvent) -> Self {
        Self::Kadmelia(e)
    }
}

impl From<ProxyClientEvent> for ClientEvent {
    fn from(e: ProxyClientEvent) -> Self {
        Self::Client(e)
    }
}

impl From<IdentifyEvent> for ClientEvent {
    fn from(e: IdentifyEvent) -> Self {
        Self::Ident(e)
    }
}

impl From<relay::v2::client::Event> for ClientEvent {
    fn from(e: relay::v2::client::Event) -> Self {
        Self::Relay(e)
    }
}

pub async fn run_client(
    key: PrivateKey,
    local_addr: SocketAddr,
    remote_peer: PeerId,
    remote_addr: SocketAddr,
) -> Result<(), Box<dyn Error>> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    let (relay_transport, client) =
        relay::v2::client::Client::new_transport_and_behaviour(local_peer_id);

    let noise_keys = noise::Keypair::<noise::X25519Spec>::new()
        .into_authentic(&local_key)
        .expect("Signing libp2p-noise static DH keypair failed.");

    let transport = OrTransport::new(
        relay_transport,
        block_on(DnsConfig::system(TcpTransport::new(
            GenTcpConfig::default().port_reuse(true),
        )))
        .unwrap(),
    )
    .upgrade(upgrade::Version::V1)
    .authenticate(noise::NoiseConfig::xx(noise_keys).into_authenticated())
    .multiplex(libp2p::yamux::YamuxConfig::default())
    .boxed();

    let mut swarm = {
        let mut cfg = KademliaConfig::default();
        cfg.set_query_timeout(Duration::from_secs(5 * 60));
        let store = MemoryStore::new(local_peer_id);
        let mut kadmelia = Kademlia::with_config(local_peer_id, store, cfg);

        let mut behaviour = ClientBehaviour {
            client: ProxyClient::new(key),
            kadmelia,
            relay: client,
            ident: Identify::new(IdentifyConfig::new(
                "/ipfs/0.1.0".into(),
                local_key.public(),
            )),
        };

        // Add the bootnodes to the local routing table. `libp2p-dns` built
        // into the `transport` resolves the `dnsaddr` when Kademlia tries
        // to dial these nodes.
        let bootaddr = Multiaddr::from_str("/dnsaddr/bootstrap.libp2p.io")?;

        for peer in &BOOTNODES {
            behaviour
                .kadmelia
                .add_address(&PeerId::from_str(peer)?, bootaddr.clone());
        }
        Swarm::new(transport, behaviour, local_peer_id)
    };

    swarm
        .behaviour_mut()
        .kadmelia
        .get_closest_peers(remote_peer);
    let mut dialed = false;

    loop {
        let event = swarm.select_next_some().await;
        match event {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } if peer_id == remote_peer => {
                if !dialed {
                    info!("remote_peer={remote_peer}");
                    dialed = true;
                    swarm.dial(endpoint.get_remote_address().clone())?;
                }
                if endpoint.is_dialer() {
                    info!("Starting proxy...");
                    info!("endpoint.is_dialer={remote_peer}");
                    swarm
                        .behaviour_mut()
                        .client
                        .connect(local_addr, remote_addr, remote_peer);
                }
            }
            _ => {}
        }
    }
}
