use std::{fmt::Display, net::Ipv4Addr};

use chrono::Local;
use network_types::ip::IpProto;
use sniff_common::{Flow, ProtoHdr, RawPacket};

#[derive(Debug)]
pub struct FlowPacket {
    pub flow: Flow,
    pub pkt: Packet,
}

#[derive(Debug)]
pub struct Packet {
    pub proto: IpProto,

    pub src_ip: Ipv4Addr,
    pub source: u16,
    pub dst_ip: Ipv4Addr,
    pub dst: u16,
    pub length: u16,
}

impl From<[u8; RawPacket::LEN]> for Packet {
    fn from(value: [u8; RawPacket::LEN]) -> Self {
        let raw_pkt = value.as_ptr() as *const RawPacket;
        let ip_hdr = unsafe { (*raw_pkt).ip_hdr };
        let length = u16::from_be(ip_hdr.tot_len);
        let src_ip = Ipv4Addr::from(u32::from_be(ip_hdr.src_addr));
        let dst_ip = Ipv4Addr::from(u32::from_be(ip_hdr.dst_addr));
        match unsafe { &(*raw_pkt).proto_hdr } {
            ProtoHdr::Tcp(tcp_hdr) => {
                let source = u16::from_be(tcp_hdr.source);
                let dst = u16::from_be(tcp_hdr.dest);
                Self {
                    src_ip,
                    dst_ip,
                    source,
                    dst,
                    length,
                    proto: IpProto::Tcp,
                }
            }
            ProtoHdr::Udp(udp_hdr) => {
                let source = u16::from_be(udp_hdr.source);
                let dst = u16::from(udp_hdr.dest);
                Self {
                    src_ip,
                    dst_ip,
                    source,
                    dst,
                    length,
                    proto: IpProto::Udp,
                }
            }
        }
    }
}

impl Display for FlowPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let now = Local::now();
        write!(
            f,
            "* {:<22}{:<10}{:<23} ->    {:<24}{:<7}length={:<5}",
            now.format("[%Y-%m-%d %H:%M:%S]").to_string(),
            format!("{:?}", self.flow),
            format!("{}:{}", self.pkt.src_ip, self.pkt.source),
            format!("{}:{}", self.pkt.dst_ip, self.pkt.dst),
            format!("{:?}", self.pkt.proto),
            self.pkt.length,
        )
    }
}
