extern crate pnet;

use std::net::Ipv4Addr;
use std::net::IpAddr;

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

pub fn do_traceroute(
    target: Ipv4Addr,
    hops: u8
) -> Result<(), String> {
    let (mut us, mut ur) = transport::transport_channel(
        65535,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp)
    ).map_err(|e| e.to_string())?;

    let mut ur = transport::ipv4_packet_iter(&mut ur);

    for hop in 1..hops + 1 {
        let echo_request = gen_echo_request(
            target,
            hop
        ).ok_or("Failed: generate ICMP packet.".to_string())?;
        us.send_to(echo_request, IpAddr::V4(target)).map_err(|e| e.to_string())?;

        let s = ur.next()
            .ok()
            .map_or(
                "###.###.###.###".to_string(),
                |n| n.0.get_source().to_string()
            );
        println!(" {: >2} {}", hop, s);
        if s == target.to_string() {
            return Ok(())
        }
    }

    Ok(())
}

fn gen_echo_request<'a>(
    dest: Ipv4Addr,
    ttl: u8
) -> Option<MutableIpv4Packet <'a>> {
    let ipv4_raw_packet = vec![0u8; IP_TOTAL_LENGTH];
    let mut ipv4_packet = MutableIpv4Packet::owned(ipv4_raw_packet)?;
    // IPv4
    ipv4_packet.set_version(4);
    // Internet header length in 32-bit words
    ipv4_packet.set_header_length((IP_HEADER_LENGTH * 8 / 32) as u8);
    ipv4_packet.set_total_length(IP_TOTAL_LENGTH as u16);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(dest);

    let icmp_raw_packet = vec![0u8; ICMP_HEADER_LENGTH];
    let mut icmp_packet = MutableEchoRequestPacket::owned(icmp_raw_packet)?;
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_identifier(0);
    icmp_packet.set_sequence_number(0);
    let checksum = icmp::checksum(&IcmpPacket::new(icmp_packet.packet())?);
    icmp_packet.set_checksum(checksum);

    ipv4_packet.set_payload(icmp_packet.packet());
    Some(ipv4_packet)
}
