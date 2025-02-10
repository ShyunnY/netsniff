use std::{fmt::Display, net::Ipv4Addr};

use network_types::ip::IpProto;
use sniff_common::{ProtoHdr, RawPacket};

// TODO: 添加更多信息?
pub struct Packet {
    pub proto: IpProto,

    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub length: u16,
}

impl From<[u8; RawPacket::LEN]> for Packet {
    fn from(value: [u8; RawPacket::LEN]) -> Self {
        let raw_pkt = value.as_ptr() as *const RawPacket;
        let ip_hdr = unsafe { (*raw_pkt).ip_hdr };
        let length = ip_hdr.tot_len;
        match unsafe { &(*raw_pkt).proto_hdr } {
            ProtoHdr::Tcp(tcp_hdr) => {
                let src_ip = Ipv4Addr::from(u32::from_be(ip_hdr.src_addr));
                let dst_ip = Ipv4Addr::from(u32::from_be(ip_hdr.dst_addr));
                let length = u16::from_be(ip_hdr.tot_len);
                Self {
                    src_ip,
                    dst_ip,
                    length,
                    proto: IpProto::Tcp,
                }
            }
            ProtoHdr::Udp(udp_hdr) => {
                let src_ip = Ipv4Addr::from(u32::from_be(ip_hdr.src_addr));
                let dst_ip = Ipv4Addr::from(u32::from_be(ip_hdr.dst_addr));
                let length = u16::from_be(ip_hdr.tot_len);

                Self {
                    src_ip,
                    dst_ip,
                    length,
                    proto: IpProto::Udp,
                }
            }
        }
    }
}

impl Display for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Ingress: {} -> {}, length: {}",
            self.src_ip, self.dst_ip, self.length
        )
    }
}
