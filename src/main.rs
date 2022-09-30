use std::{env, io};
use std::error::Error;
use libp2p::{Multiaddr, PeerId, Swarm};
use libp2p::futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use rand::SeedableRng;
use ssh_key::private::{KeypairData, RsaKeypair, RsaPrivateKey};
use ssh_key::{Algorithm, PrivateKey};
use crate::handler::ProxyClient;
use crate::server_handler::ProxyServer;

mod client;
mod handler;
mod protocol;
mod server;
mod server_handler;

const SEED: [u8; 32] = [1 as u8; 32];

#[async_std::main]
async fn main() -> Result<(), Box<dyn Error>> {
    pretty_env_logger::init();
    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("Local peer id: {:?}", local_peer_id);

    let transport = libp2p::development_transport(local_key).await?;

    let key = PrivateKey::random(rand::rngs::StdRng::from_seed(SEED), Algorithm::Ed25519)?;


    match env::args().nth(1).unwrap().as_str() {
        "server" => {
            let behaviour = ProxyServer{key: key.public_key().clone()};
            let mut swarm = Swarm::new(transport, behaviour, local_peer_id);
            swarm.listen_on("/ip4/0.0.0.0/tcp/1111".parse()?)?;

            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {:?}", address),
                    SwarmEvent::Behaviour(event) => println!("{:?}", event),
                    _ => {}
                }
            }

        },
        _ => {
            let behaviour = ProxyClient::new(key);
            let mut swarm = Swarm::new(transport, behaviour, local_peer_id);
            swarm.listen_on("/ip4/0.0.0.0/tcp/2222".parse()?)?;

            let addr = env::args().nth(2).unwrap();
            let remote: Multiaddr = addr.parse()?;
            swarm.dial(remote)?;
            println!("Dialed {}", addr);

            swarm.behaviour_mut().connect("127.0.0.1:2392".parse()?, "142.250.74.142:80".parse()?, env::args().nth(3).unwrap().parse()?);

            loop {
                match swarm.select_next_some().await {
                    SwarmEvent::NewListenAddr { address, .. } => println!("Listening on {:?}", address),
                    SwarmEvent::Behaviour(event) => println!("{:?}", event),
                    _ => {}
                }
            }
        }
    }
}
