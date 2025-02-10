use aya_ebpf::{cty::c_long, programs::TcContext};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use sniff_common::{ProtoHdr, RawPacket};

use crate::util;

pub(crate) fn try_sniff(ctx: &TcContext) -> Result<(), c_long> {
    let eth_hdr: EthHdr = ctx.load(0)?;

    match eth_hdr.ether_type {
        EtherType::Ipv4 => {
            let ipv4_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN)?;
            match ipv4_hdr.proto {
                IpProto::Tcp if util::is_tcp() => {
                    let tcp_hdr: *const TcpHdr =
                        util::ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| -1)?;
                    util::submit(RawPacket::new(ipv4_hdr, ProtoHdr::Tcp(unsafe { *tcp_hdr })));
                }
                IpProto::Udp if util::is_udp() => {
                    let udp_hdr: *const UdpHdr =
                        util::ptr_at(ctx, EthHdr::LEN + Ipv4Hdr::LEN).map_err(|_| -1)?;
                    util::submit(RawPacket::new(ipv4_hdr, ProtoHdr::Udp(unsafe { *udp_hdr })));
                }
                _ => {}
            }
        }
        _ => {}
    }

    Ok(())
}
