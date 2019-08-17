extern crate pnet;

use std::env;
use std::net::IpAddr;
use std::net::Ipv4Addr;

use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::icmp;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::transport;
use pnet::transport::TransportChannelType;

const IP_HEADER_LENGTH: usize = 20;
const ICMP_HEADER_LENGTH: usize = 8;
const IP_TOTAL_LENGTH: usize = IP_HEADER_LENGTH + ICMP_HEADER_LENGTH;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("Failed: specify destination IPv4 address.");
    }

    let target: Ipv4Addr = args[1].parse()
        .expect("Failed: invalid IPv4 address format.");

    let mut ipv4_raw_packet = [0u8; IP_TOTAL_LENGTH];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_raw_packet).unwrap();
    // IPv4
    ipv4_packet.set_version(4);
    // Internet header length in 32-bit words
    ipv4_packet.set_header_length((IP_HEADER_LENGTH * 8 / 32) as u8);
    ipv4_packet.set_total_length(IP_TOTAL_LENGTH as u16);
    ipv4_packet.set_ttl(32);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(target);

    let mut icmp_raw_packet = [0u8; ICMP_HEADER_LENGTH];
    let mut icmp_packet = MutableEchoRequestPacket::new(&mut icmp_raw_packet).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_identifier(0);
    icmp_packet.set_sequence_number(0);
    let checksum = icmp::checksum(&IcmpPacket::new(icmp_packet.packet()).unwrap());
    icmp_packet.set_checksum(checksum);
    ipv4_packet.set_payload(&icmp_raw_packet);

    let (mut us, _) = transport::transport_channel(
        65536,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp)
    ).expect("Failed: generate transport channel.");
    us.send_to(ipv4_packet, IpAddr::V4(target));
}
