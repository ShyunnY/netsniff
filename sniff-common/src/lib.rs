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

#[derive(Debug, Clone, Copy)]
pub enum Flow {
    All,
    Ingress,
    Egress,
}

impl From<i32> for Flow {
    fn from(value: i32) -> Self {
        match value {
            1 => Flow::Ingress,
            2 => Flow::Egress,
            _ => Flow::All,
        }
    }
}
