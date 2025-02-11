#![no_std]

use core::mem;

use network_types::{ip::Ipv4Hdr, tcp::TcpHdr, udp::UdpHdr};

#[repr(C)]
pub struct RawPacket {
    pub ip_hdr: Ipv4Hdr,
    pub proto_hdr: ProtoHdr,
}

#[repr(C)]
pub enum ProtoHdr {
    Tcp(TcpHdr),
    Udp(UdpHdr),
}

impl RawPacket {
    pub const LEN: usize = mem::size_of::<Self>();

    pub fn new(ip_hdr: Ipv4Hdr, proto_hdr: ProtoHdr) -> Self {
        Self { ip_hdr, proto_hdr }
    }
}

#[derive(Debug)]
pub enum Flow {
    Ingress,
    Egress,
    All,
}
