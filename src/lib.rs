#[macro_use]
extern crate log;
extern crate nix;
extern crate rand;

use nix::ifaddrs::InterfaceAddress;
use nix::sys::socket::{InetAddr, SockAddr};
use rand::{ThreadRng, Rng};
use std::collections::HashMap;
use std::net::{IpAddr, UdpSocket};
use std::sync::{Arc, Mutex};

pub const MIN_EPHEMERAL_PORT : u16 = 49152;
pub const MAX_EPHEMERAL_PORT : u16 = 65535;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CandidateType {
    Host,
    ServerReflexive,
    PeerReflexive,
    Relay
}

fn cand_type_as_sdp(cand_type: &CandidateType) -> String {
    match cand_type {
        Host => "host".to_string(),
        ServerReflexive => "srflx".to_string(),
        PeerReflexive => "prflx".to_string(),
        Relay => "relay".to_string()
    }
}

fn to_type_preference(cand: &CandidateType) -> u32 {
    match cand {
        CandidateType::Host => 126,
        CandidateType::ServerReflexive => 100,
        CandidateType::PeerReflexive => 2,
        CandidateType::Relay => 0
    }
}

#[derive(Debug)]
pub enum CandidateSocket {
    Udp(UdpSocket),
    //Tcp(TcpStream) //TODO: Tcp
}

#[derive(Clone, Debug)]
pub struct Candidate {
    candidate_type: CandidateType,
    candidate_socket: Arc<Mutex<CandidateSocket>>,
    component_id: usize,
    foundation: String
}

impl Candidate {
    fn new(cand_type: CandidateType, socket: Arc<Mutex<CandidateSocket>>, component_id: usize, foundation: String) -> Candidate {
        Candidate {
            candidate_type: cand_type,
            candidate_socket: socket,
            component_id: component_id,
            foundation: foundation
        }
    }

    /// Gets the candidate's type preference.
    pub fn get_type_preference(&self) -> u32 {
        to_type_preference(&self.candidate_type)
    }

    /// Gets the candidate's local preference.
    pub fn get_local_preference(&self) -> u32 {
        0
    }

    /// Gets the priority of this candidate based on its type & local preference and its component
    /// id.
    pub fn get_priority(&self) -> u32 {
        0x1000000 * self.get_type_preference() + 0x100 * self.get_local_preference() + (0x100 - self.component_id as u32)
    }

    /// Converts this candidate into an SDP a= line. Format should be:
    /// a=candidate:foundation component-id transport priority connection-address
    /// port candidate-type [relative address?] [relative port?]
    /// *(extension-attribute-name extension-attribute-value)
    pub fn as_sdp(&self) -> String {
        // a=candidate:foundation component-id transport priority connection-address
        // port candidate-type [relative address?] [relative port?]
        // *(extension-attribute-name extension-attribute-value)
        let (conn_addr, port) = match *self.candidate_socket.lock().unwrap() {
            CandidateSocket::Udp(ref s) => {
                let local_addr = s.local_addr().unwrap();
                (local_addr.ip().to_string(), local_addr.port().to_string())
            },
            //_      => "unknown".to_string()
        };
        format!("a=candidate:{} {} {} {} {} {} typ {}", self.foundation, self.component_id, "udp", self.get_priority(),
            conn_addr, port, cand_type_as_sdp(&self.candidate_type))
    }
}

#[derive(Debug)]
struct Component {
    component_id: usize,
    candidates: Vec<Candidate>
}

impl Component {
    pub fn new(cid: usize) -> Component {
        Component {
            component_id: cid,
            candidates: vec![]
        }
    }

    pub fn add_candidate(&mut self, candidate: Candidate) {
        self.candidates.push(candidate);
    }
}

#[derive(Debug)]
pub struct ICEStream {
    pub id: usize,
    pub num_components: usize,
    components: Vec<Component>
}

impl ICEStream {
    fn new(id: usize, num_components: usize) -> ICEStream {
        let components = (0..num_components).map(|c| Component::new(c)).collect();
        ICEStream {
            id: id,
            num_components: num_components,
            components: components,
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
enum SockType { Udp, Tcp }

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct Foundation {
    candidate_type: CandidateType,
    ip: IpAddr,
    server: Option<String>, // If srflx/relay, the server addr
    sock_type: SockType
}


#[derive(Debug)]
pub struct Agent {
    streams: Vec<ICEStream>,
    min_port: u16,
    max_port: u16,
    local_addrs: Option<Vec<InterfaceAddress>>,
}

fn choose_port(rng: &mut ThreadRng, min_port: u16, max_port: u16) -> u16 {
    rng.gen_range(min_port, max_port)
}

impl Agent {
    pub fn new(min_port: u16, max_port: u16) -> Agent {
        Agent {
            min_port: min_port,
            max_port: max_port,
            streams: vec![],
            local_addrs: None
        }
    }

    /// Adds a new stream to the ICE Agent.
    /// Takes the number of components to add to the stream and returns the new stream's
    /// ID.
    pub fn add_stream(&mut self, num_components: usize) -> usize {
        let stream_id = self.streams.len() + 1;
        let stream = ICEStream::new(stream_id, num_components);
        self.streams.push(stream);
        stream_id
    }

    /// Gathers candidates and returns them in a vector. If there is a failure, it will return a
    /// human readable string.
    pub fn gather_candidates(&mut self, stream_id: usize) -> Result<Vec<Candidate>, String> {
        if self.local_addrs.is_none() {
            debug!("Gathering local addrs");
            self.local_addrs = Some(self.discover_local_ips()?);
        }
        let stream_components = self.streams[stream_id-1].num_components;
        let mut rng = rand::thread_rng();
        let mut candidates = vec![];
        let mut foundation_strings : HashMap<Foundation, String> = HashMap::new();
        let mut string_foundations : HashMap<String, Foundation> = HashMap::new();
        //let mut gathering_state = GatheringState::Host;
        let candidate_type = CandidateType::Host;
        for component_id in 0..stream_components {
            for addr in self.local_addrs.as_ref().unwrap() {
                let socket = self.attempt_socket_bind(&mut rng, addr);
                if let Ok(s) = socket {
                    debug!("Successfully bound to socket addr {:?}", s);
                    let foundation = Foundation {
                        candidate_type: candidate_type.clone(),
                        ip: s.local_addr().unwrap().ip().clone(),
                        server: None,
                        sock_type: SockType::Udp
                    };
                    let foundation_str = match foundation_strings.get(&foundation) {
                        Some(f) => f.clone(),
                        None => {
                            let found;
                            loop {
                                let f = rng.gen_range(0, std::u16::MAX).to_string();
                                if string_foundations.contains_key(&f) {
                                    continue;
                                } else {
                                    string_foundations.insert(f.clone(), foundation.clone());
                                    foundation_strings.insert(foundation.clone(), f.clone());
                                    found = f;
                                    break;
                                }
                            }
                            found
                        }
                    };
                    let candidate = Candidate::new(candidate_type.clone(),
                                                   Arc::new(Mutex::new(CandidateSocket::Udp(s))),
                                                   component_id,
                                                   foundation_str);
                    let component = &mut self.streams[stream_id-1].components[component_id];
                    component.add_candidate(candidate.clone());
                    candidates.push(candidate);
                }
            }
        }
        Ok(candidates)
    }

    /// Sets candidates gotten from the remote peer on the agent for the given stream.
    pub fn set_remote_candidates(&mut self, stream_id: usize, candidates: Vec<Candidate>) {
    }

    fn attempt_socket_bind(&self, rng: &mut ThreadRng, addr: &InterfaceAddress) -> Result<UdpSocket, String> {
        for i in 0..3 {
            let port = choose_port(rng, self.min_port, self.max_port);
            let sockaddr = addr.address.unwrap().clone(); // SockAddr::Inet
            let bind_addr = match sockaddr {
                SockAddr::Inet(inet_addr) => {
                    match inet_addr {
                        InetAddr::V4(sockaddr_in) => {
                            let mut new_addr = sockaddr_in.clone();
                            new_addr.sin_port = port;
                            Ok(InetAddr::V4(new_addr).to_std())
                        }
                        InetAddr::V6(sockaddr_in6) => {
                            let mut new_addr = sockaddr_in6.clone();
                            new_addr.sin6_port = port;
                            Ok(InetAddr::V6(new_addr).to_std())
                        }
                    }
                },
                _ => Err("Not Inet address")
            }?;
            match UdpSocket::bind(bind_addr) {
                Ok(s) => return Ok(s),
                Err(err) => {
                    error!("Attempt #{} Failed to bind to addr {}: {}", i, bind_addr, err);
                }
            }
        }
        Err("Failed to find a socket to bind to".to_string())
    }

    fn discover_local_ips(&mut self) -> Result<Vec<InterfaceAddress>, String> {
        let addrs = nix::ifaddrs::getifaddrs()
            .map_err(|e| format!("Error at begin getting ifaddrs: {}", e))?;
        let local_addrs = addrs
            .filter(|iface| iface.address.is_some() && iface.destination.is_none())
            .filter(|iface| iface.flags.contains(nix::net::if_::InterfaceFlags::IFF_UP))
            .filter(|iface| !iface.flags.contains(nix::net::if_::InterfaceFlags::IFF_LOOPBACK)) // TODO: option for loopback
            .filter(|iface| if let SockAddr::Inet(_) = iface.address.unwrap() { true } else { false })
            .collect();
        Ok(local_addrs)
    }
}
