use aya_ebpf::{macros::map, maps::RingBuf};
use sniff_common::RawPacket;

#[map(name = "PACKET_DATA")]
pub(crate) static PACKET_DATA: RingBuf = RingBuf::with_byte_size(4096 * RawPacket::LEN as u32, 0);
