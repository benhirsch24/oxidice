#[macro_use]
extern crate log;
#[macro_use]
extern crate nom;
use nom::{rest};

extern crate nix;
extern crate rand;

use nix::ifaddrs::InterfaceAddress;
use nix::sys::socket::{InetAddr, SockAddr};
use rand::{ThreadRng, Rng};
use std::collections::HashMap;
use std::net::{AddrParseError, IpAddr, SocketAddr, UdpSocket};
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
        CandidateType::Host => "host".to_string(),
        CandidateType::ServerReflexive => "srflx".to_string(),
        CandidateType::PeerReflexive => "prflx".to_string(),
        CandidateType::Relay => "relay".to_string()
    }
}

fn to_type_preference(cand: &CandidateType) -> u64 {
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
    candidate_socket: Option<Arc<Mutex<CandidateSocket>>>,
    candidate_addr: SocketAddr,
    component_id: usize,
    foundation: String,
    priority: u64
}

impl Candidate {
    fn new(cand_type: CandidateType,
           socket: Option<Arc<Mutex<CandidateSocket>>>,
           sock_addr: SocketAddr,
           component_id: usize,
           foundation: String,
           priority_opt: Option<u64>) -> Candidate
    {
        let mut c = Candidate {
            candidate_type: cand_type,
            candidate_socket: socket,
            candidate_addr: sock_addr,
            component_id: component_id,
            foundation: foundation,
            priority: 0
        };
        match priority_opt {
            Some(p) => c.priority = p,
            None => c.compute_priority()
        };
        c
    }

    /// Gets the candidate's type preference.
    pub fn get_type_preference(&self) -> u64 {
        to_type_preference(&self.candidate_type)
    }

    /// Gets the candidate's local preference.
    pub fn get_local_preference(&self) -> u64 {
        0
    }

    /// Gets the priority of this candidate based on its type & local preference and its component
    /// id.
    pub fn compute_priority(&mut self) {
        self.priority = 0x1000000 * self.get_type_preference() + 0x100 * self.get_local_preference() + (0x100 - self.component_id as u64);
    }

    /// Converts this candidate into an SDP a= line. Format should be:
    /// a=candidate:foundation component-id transport priority connection-address
    /// port candidate-type [relative address?] [relative port?]
    /// *(extension-attribute-name extension-attribute-value)
    pub fn as_sdp(&self) -> String {
        // a=candidate:foundation component-id transport priority connection-address
        // port candidate-type [relative address?] [relative port?]
        // *(extension-attribute-name extension-attribute-value)
        format!("a=candidate:{} {} {} {} {} {} typ {}", self.foundation, self.component_id, "udp", self.priority,
            self.candidate_addr.ip(), self.candidate_addr.port(), cand_type_as_sdp(&self.candidate_type))
    }
}

fn is_digit(c: char) -> bool {
    c.is_digit(10)
}

named!(i32_parse<&str, i32>,
       map_res!(
           take_while!(is_digit),
                |s: &str| s.parse::<i32>()));

named!(u16_parse<&str, u16>,
       map_res!(
           take_while!(is_digit),
                |s: &str| s.parse::<u16>()));

named!(u64_parse<&str, u64>,
       map_res!(
           take_while!(is_digit),
                |s: &str| s.parse::<u64>()));

fn cand_type_from_str(s: &str) -> Option<CandidateType> {
    match s {
        "host"  => Some(CandidateType::Host),
        "srflx" => Some(CandidateType::ServerReflexive),
        "prflx" => Some(CandidateType::PeerReflexive),
        "relay" => Some(CandidateType::Relay),
        _ => None
    }
}

named!(candidate_sdp_parser<&str, Candidate>, do_parse!(
        tag_s!("a=candidate:") >>
        foundation: take_until!(" ") >>
        component_id: ws!(i32_parse) >>
        transport: ws!(alt!(tag_s!("udp") | tag_s!("tcp"))) >>
        priority: ws!(u64_parse) >>
        conn_addr: map_res!(take_until!(" "), |s: &str| -> Result<IpAddr, AddrParseError> { s.parse()}) >>
        port: ws!(u16_parse) >>
        tag_s!("typ ") >> cand_type: map_opt!(rest, cand_type_from_str) >>
        (Candidate::new(cand_type,
                        None,
                        SocketAddr::new(conn_addr, port),
                        component_id as usize,
                        foundation.to_string(),
                        Some(priority)))
        ));

pub fn candidate_from_sdp(candidate_str: &str) -> Option<Candidate> {
    match candidate_sdp_parser(candidate_str) {
        Ok((_, r)) => Some(r),
        Err(e) => match e {
            nom::Err::Incomplete(n) => {
                println!("Incomplete candidate parsing: {:?}", n);
                None
            },
            nom::Err::Error(ctx) => {
                println!("Error when parsing candidate {:?}", ctx);
                None
            }
            nom::Err::Failure(ctx) => {
                println!("Failure when parsing candidate {:?}", ctx);
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn sdp_parser_test() {
        let sdp = "a=candidate:4000 1 udp 1212 127.0.0.1 8000 typ host";
        let parsed_candidate = match super::candidate_sdp_parser(sdp) {
            Ok((_, r)) => r,
            Err(e) => match e {
                nom::Err::Incomplete(n) => panic!("Needed: {:?}", n),
                nom::Err::Error(ctx) => panic!("ERROR {:?}", ctx),
                nom::Err::Failure(ctx) => panic!("Failure {:?}", ctx)
            }
        };
        assert_eq!(parsed_candidate.candidate_type, super::CandidateType::Host);
        assert_eq!(parsed_candidate.component_id, 1);
        assert_eq!(parsed_candidate.foundation, "4000".to_string());
        assert_eq!(parsed_candidate.priority, 1212);
        assert_eq!(parsed_candidate.candidate_addr, super::SocketAddr::new("127.0.0.1".parse().unwrap(), 8000));
    }
}

#[derive(Debug)]
struct Component {
    component_id: usize,
    candidates: Vec<Candidate>,
    remote_candidates: Vec<Candidate>,
}

impl Component {
    pub fn new(cid: usize) -> Component {
        Component {
            component_id: cid,
            candidates: vec![],
            remote_candidates: vec![],
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
                let socket = self.attempt_socket_bind(&mut rng, addr)?;
                debug!("Successfully bound to socket addr {:?}", socket);
                let foundation = Foundation {
                    candidate_type: candidate_type.clone(),
                    ip: socket.local_addr().unwrap().ip().clone(),
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
                let addr = socket.local_addr().unwrap().clone();
                let candidate = Candidate::new(candidate_type.clone(),
                    Some(Arc::new(Mutex::new(CandidateSocket::Udp(socket)))),
                    addr,
                    component_id,
                    foundation_str,
                    None);
                let component = &mut self.streams[stream_id-1].components[component_id];
                component.add_candidate(candidate.clone());
                candidates.push(candidate);
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
