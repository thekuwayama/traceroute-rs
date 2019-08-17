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
    let (mut us, _) = match transport::transport_channel(
        65535,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp)
    ) {
        Ok((us, ur)) => (us, ur),
        Err(err) => return Err(err.to_string())
    };

    for hop in 1..hops + 1 {
        let mut ipv4_raw_packet = [0u8; IP_TOTAL_LENGTH];
        let mut icmp_raw_packet = [0u8; ICMP_HEADER_LENGTH];
        let echo_request = match gen_echo_request(
            &mut ipv4_raw_packet[..],
            &mut icmp_raw_packet[..],
            target,
            hop
        ) {
            Some(packet) => packet,
            None => return Err("Failed: generate ICMP packet.".to_string())
        };
        us.send_to(echo_request, IpAddr::V4(target));
        // recv && print echo_reply
    }

    Ok(())
}

fn gen_echo_request<'a>(
    ipv4_raw_packet: &'a mut[u8],
    icmp_raw_packet: &'a mut[u8],
    dest: Ipv4Addr,
    ttl: u8
) -> Option<MutableIpv4Packet <'a>> {
    debug_assert_eq!(ipv4_raw_packet.len(), IP_TOTAL_LENGTH);
    debug_assert_eq!(icmp_raw_packet.len(), ICMP_HEADER_LENGTH);

    let mut ipv4_packet = MutableIpv4Packet::new(ipv4_raw_packet)?;
    // IPv4
    ipv4_packet.set_version(4);
    // Internet header length in 32-bit words
    ipv4_packet.set_header_length((IP_HEADER_LENGTH * 8 / 32) as u8);
    ipv4_packet.set_total_length(IP_TOTAL_LENGTH as u16);
    ipv4_packet.set_ttl(ttl);
    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_destination(dest);

    let mut icmp_packet = MutableEchoRequestPacket::new(icmp_raw_packet)?;
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_identifier(0);
    icmp_packet.set_sequence_number(0);
    let checksum = icmp::checksum(&IcmpPacket::new(icmp_packet.packet())?);
    icmp_packet.set_checksum(checksum);

    ipv4_packet.set_payload(&icmp_raw_packet);
    Some(ipv4_packet)
}
