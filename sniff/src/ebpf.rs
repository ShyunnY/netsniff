use aya::{
    include_bytes_aligned,
    maps::RingBuf,
    programs::{tc, SchedClassifier},
    EbpfLoader,
};
use libc::{self, c_int};
use log::{error, info, warn};
use sniff_common::{Flow, RawPacket};
use tokio::{
    io::{unix::AsyncFd, Interest},
    sync::mpsc,
};

use crate::network::{NetworkPacket, Packet};

pub async fn load_ingress_sched_cls(iface: String, proto: i32, tx: mpsc::Sender<NetworkPacket>) {
    let ret = set_rlimit();
    if ret != 0 {
        error!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut ebpf = match EbpfLoader::new()
        .set_global("SNIFF_PROTOCOL", &proto, true)
        .load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/",
            env!("CARGO_PKG_NAME"),
        ))) {
        Ok(ebpf) => ebpf,
        Err(e) => {
            println!("{}", e);
            error!(
                "failed to load the ingress eBPF program(TC) bytecode by error: {}",
                e
            );
            return;
        }
    };

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize kernel eBPF logger: {}", e);
    }

    let _ = tc::qdisc_add_clsact(&iface);
    let prog: &mut SchedClassifier = ebpf.program_mut("sniff").unwrap().try_into().unwrap();
    if let Err(e) = prog.load() {
        error!(
            "failed to load the ingress eBPF program(TC) to the kernel by error: {}",
            e
        );
        return;
    };

    if let Err(e) = prog.attach(&iface, tc::TcAttachType::Ingress) {
        error!(
            "failed to attach the ingress eBPF program(TC) to the '{}' network interface by error: {}",
            iface,
            e
        );
        return;
    } else {
        info!(
            "success to attach the ingress eBPF program(TC) to the '{}' network interface!",
            iface
        );
    }

    let map = match RingBuf::try_from(ebpf.map_mut("PACKET_DATA").unwrap()) {
        Ok(map) => map,
        Err(e) => {
            error!(
                "failed to load the ingress eBPF program(TC) RingBuf by error: {}",
                e
            );
            return;
        }
    };

    let mut fd = AsyncFd::new(map).unwrap();
    loop {
        let mut guard = fd.ready_mut(Interest::READABLE).await.unwrap();
        let ring_buf = guard.get_inner_mut();
        while let Some(raw_pkt) = ring_buf.next() {
            let raw_pkt: [u8; RawPacket::LEN] = raw_pkt.to_owned().try_into().unwrap();
            let packet: Packet = raw_pkt.into();

            tx.send(NetworkPacket {
                iface: iface.to_owned(),
                flow: Flow::Ingress,
                pkt: packet,
            })
            .await
            .expect("failed to send packet to rx by closed channel");
        }
        guard.clear_ready();
    }
}

pub async fn load_egress_sched_cls(iface: String, proto: i32, tx: mpsc::Sender<NetworkPacket>) {
    let ret = set_rlimit();
    if ret != 0 {
        error!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let mut ebpf = match EbpfLoader::new()
        .set_global("SNIFF_PROTOCOL", &proto, true)
        .load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/",
            env!("CARGO_PKG_NAME"),
        ))) {
        Ok(ebpf) => ebpf,
        Err(e) => {
            println!("{}", e);
            error!(
                "failed to load the egress eBPF program(TC) bytecode by error: {}",
                e
            );
            return;
        }
    };

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize kernel eBPF logger: {}", e);
    }

    let _ = tc::qdisc_add_clsact(&iface);
    let prog: &mut SchedClassifier = ebpf.program_mut("sniff").unwrap().try_into().unwrap();
    if let Err(e) = prog.load() {
        error!(
            "failed to load the egress eBPF program(TC) to the kernel by error: {}",
            e
        );
        return;
    };

    if let Err(e) = prog.attach(&iface, tc::TcAttachType::Egress) {
        error!(
            "failed to attach the egress eBPF program(TC) to the '{}' network interface by error: {}",
            iface, e
        );
        return;
    } else {
        info!(
            "success to attach the egress eBPF program(TC) to the '{}' network interface!",
            iface
        );
    }

    let map = match RingBuf::try_from(ebpf.map_mut("PACKET_DATA").unwrap()) {
        Ok(map) => map,
        Err(e) => {
            error!(
                "failed to load the egress eBPF program(TC) RingBuf by error: {}",
                e
            );
            return;
        }
    };

    let mut fd = AsyncFd::new(map).unwrap();
    loop {
        let mut guard = fd.ready_mut(Interest::READABLE).await.unwrap();
        let ring_buf = guard.get_inner_mut();
        while let Some(raw_pkt) = ring_buf.next() {
            let raw_pkt: [u8; RawPacket::LEN] = raw_pkt.to_owned().try_into().unwrap();
            let packet: Packet = raw_pkt.into();

            tx.send(NetworkPacket {
                iface: iface.to_owned(),
                flow: Flow::Egress,
                pkt: packet,
            })
            .await
            .expect("failed to send packet to rx by closed channel");
        }
        guard.clear_ready();
    }
}

pub fn check_attach(iface: String, flow: Flow) {
    let ret = set_rlimit();
    if ret != 0 {
        error!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let attach_type = match flow {
        Flow::Ingress => tc::TcAttachType::Ingress,
        Flow::Egress => tc::TcAttachType::Egress,
        Flow::All => {
            /* this branch should not be executed */
            return;
        }
    };

    let mut ebpf = match EbpfLoader::new()
        .set_global("SNIFF_PROTOCOL", &0, true)
        .load(include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/",
            env!("CARGO_PKG_NAME"),
        ))) {
        Ok(ebpf) => ebpf,
        Err(e) => {
            println!("{}", e);
            error!(
                "failed to load the {:?} eBPF program(TC) bytecode by error: {}",
                attach_type, e
            );
            return;
        }
    };

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize kernel eBPF logger: {}", e);
    }

    let _ = tc::qdisc_add_clsact(&iface);
    let prog: &mut SchedClassifier = ebpf.program_mut("sniff").unwrap().try_into().unwrap();
    if let Err(e) = prog.load() {
        error!(
            "failed to load the {:?} eBPF program(TC) to the kernel by error: {}",
            attach_type, e
        );
        return;
    };

    if let Err(e) = prog.attach(&iface, attach_type) {
        error!(
            "failed to attach the {:?} eBPF program(TC) to the '{}' network interface by error: {}",
            attach_type, iface, e
        );
        return;
    } else {
        info!(
            "success to attach the {:?} eBPF program(TC) to the '{}' network interface!",
            attach_type, iface
        );
    }

    match RingBuf::try_from(ebpf.map_mut("PACKET_DATA").unwrap()) {
        Ok(_) => {
            info!(
                "success to load the {:?} eBPF program(TC) RingBuf!",
                attach_type
            );
        }
        Err(e) => {
            error!(
                "failed to load the {:?} eBPF program(TC) RingBuf by error: {}",
                attach_type, e
            );
            return;
        }
    };
}

#[inline]
fn set_rlimit() -> c_int {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) }
}
