use std::env;
use std::net::Ipv4Addr;

mod traceroute;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Failed: specify destination IPv4 address.");
    }

    let target: Ipv4Addr = args[1].parse()
        .expect("Failed: invalid IPv4 address format.");
    traceroute::do_traceroute(target, 1);
}
