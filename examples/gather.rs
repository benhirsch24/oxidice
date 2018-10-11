#[macro_use]
extern crate log;
extern crate byteorder;
extern crate oxidice;
extern crate simple_logger;

extern crate clap;

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use clap::{Arg, App};
use oxidice::*;
use std::io;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

fn send_candidates(stream: &mut TcpStream, candidates_sdp: &String) -> io::Result<()>{
    let candbuf = candidates_sdp.clone();
    let _ = stream.write_u64::<BigEndian>(candidates_sdp.len() as u64)?;
    stream.write(&candbuf.into_bytes())?;
    stream.flush()?;
    Ok(())
}

fn recv_candidates(stream: &mut TcpStream) -> io::Result<String> {
    let size = stream.read_u64::<BigEndian>().unwrap() as usize;
    debug!("Remote SDP is {} bytes", size);
    let mut recv_bytes = vec![0; size];
    let _ = stream.read_exact(recv_bytes.as_mut_slice())?;
    match String::from_utf8(recv_bytes) {
        Ok(s) => Ok(s.to_string()),
        Err(e) => Err(io::Error::new(io::ErrorKind::Other, format!("{}", e)))
    }
}

fn main() {
    simple_logger::init().unwrap();

    let matches = App::new("Gather ICE candidates")
        .version("1.0")
        .author("Ben Hirsch <benhirsch24@gmail.com>")
        .about("Gathers candidates, sends to remote, connects")
        .arg(Arg::with_name("recv_port")
             .short("r")
             .long("recv_port")
             .takes_value(true)
             .help("Which port to receive candidates on"))
        .arg(Arg::with_name("send_port")
             .short("s")
             .long("send_port")
             .takes_value(true)
             .help("Which port to send candidates on"))
        .get_matches();

    let mut agent = Agent::new(MIN_EPHEMERAL_PORT, MAX_EPHEMERAL_PORT);
    let stream_id = agent.add_stream(1);
    info!("Stream ID is: {}, gathering candidates", stream_id);

    let candidates = agent.gather_candidates(stream_id).unwrap();
    let candidates_sdp = {
        let candidates_sdp_vec : Vec<String> = candidates.iter().map(|c| c.as_sdp()).collect();
        let sdp_size = candidates_sdp_vec.len() + candidates_sdp_vec.iter().fold(0, |acc, cand| acc + cand.len());
        let mut candidates_sdp = String::with_capacity(sdp_size);
        for c in &candidates_sdp_vec {
            candidates_sdp.push_str(&c);
            candidates_sdp.push_str("\n");
        }
        candidates_sdp
    };
    info!("Candidate SDP: \n{}", candidates_sdp);

    // Get candidates from other source
    let remote_candidates_sdp = {
        if let Some(port) = matches.value_of("recv_port") {
            let addr = format!("127.0.0.1:{}", port);
            info!("Waiting for remote candidates on {}", port);
            let listener = TcpListener::bind(addr).unwrap();
            let (mut stream, _sock_addr) = listener.accept().unwrap();
            let remote_candidates_sdp = recv_candidates(&mut stream).unwrap();
            info!("Got remote candidates: {}", remote_candidates_sdp);

            info!("Sending local candidates.");
            let _ = send_candidates(&mut stream, &candidates_sdp).unwrap();
            remote_candidates_sdp
        } else if let Some(port) = matches.value_of("send_port") {
            let addr = format!("127.0.0.1:{}", port);
            info!("Sending candidates to {}", port);
            let mut stream = TcpStream::connect(addr).unwrap();

            // As the sender, we shall send first
            let _ = send_candidates(&mut stream, &candidates_sdp);

            // Then let's receive candidates
            let remote_candidates_sdp = recv_candidates(&mut stream).unwrap();
            info!("Got remote candidates: {}", remote_candidates_sdp);
            remote_candidates_sdp
        } else {
            panic!("Did not specify port to send or receive candidates to/from");
        }
    };

    // Now that we've exchanged candidates, convert the remote candidates
    let remote_candidates : Vec<Candidate> = remote_candidates_sdp.split('\n')
        .filter(|c| !c.is_empty())
        .map(|c| candidate_from_sdp(c).unwrap())
        .collect();
    println!("Received remote candidates: {:?}", remote_candidates);
    //agent.set_remote_candidates(stream_id, candidates);
}
