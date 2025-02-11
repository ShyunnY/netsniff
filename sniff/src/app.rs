use std::{fmt::Debug, net::IpAddr};

use colored::Colorize;
use log::info;
use network_types::ip::IpProto;
use sniff_common::Flow;
use tokio::sync::mpsc;

use crate::{cidr::PrefixTree, ebpf, network::FlowPacket, uname};

pub struct Application<N> {
    pub ifaces: Vec<String>,
    pub trie: PrefixTree<N>,

    pub rx: mpsc::Receiver<FlowPacket>,
    pub tx: mpsc::Sender<FlowPacket>,
}

impl<N> Application<N>
where
    N: Default + Clone + Debug,
{
    pub fn new(ifaces: Vec<String>, trie: PrefixTree<N>) -> Self {
        let (tx, rx) = mpsc::channel(4096 * 4096);
        Self {
            ifaces,
            trie,
            rx,
            tx,
        }
    }

    pub async fn run(&mut self, proto: i32, flow: Flow) {
        info!(
            "start sniff traffic process, flow: {:?}, kernal: {:?}",
            flow,
            uname().unwrap().release
        );

        for iface in self.ifaces.iter() {
            match flow {
                Flow::Ingress => {
                    let tx = self.fork_tx();
                    let iface = iface.to_owned();
                    tokio::spawn(async move {
                        ebpf::load_ingress_sched_cls(iface, proto, tx).await;
                    });
                }
                Flow::Egress => {
                    let tx = self.fork_tx();
                    let iface = iface.to_owned();
                    tokio::spawn(async move {
                        ebpf::load_egress_sched_cls(iface, proto, tx).await;
                    });
                }
                Flow::All => {
                    let (i_tx, e_tx) = (self.fork_tx(), self.fork_tx());
                    let (i_iface, e_iface) = (iface.to_owned(), iface.to_owned());
                    tokio::spawn(async move {
                        ebpf::load_ingress_sched_cls(i_iface, proto, i_tx).await;
                    });
                    tokio::spawn(async move {
                        ebpf::load_egress_sched_cls(e_iface, proto, e_tx).await;
                    });
                }
            }
        }

        loop {
            if let Some(flow_pkt) = self.rx.recv().await {
                let addr = match flow_pkt.flow {
                    Flow::Ingress => flow_pkt.pkt.src_ip,
                    Flow::Egress => flow_pkt.pkt.dst_ip,
                    Flow::All => {
                        /* this branch should not be executed */
                        continue;
                    }
                };

                if !self.trie.empty() {
                    let (exist, _metadata) = self.trie.search(IpAddr::V4(addr));
                    if !exist {
                        continue;
                    }
                }

                if log::log_enabled!(log::Level::Debug) {
                    let pkt_line = String::from(format!("{}", flow_pkt));
                    let output = match flow_pkt.pkt.proto {
                        IpProto::Tcp => pkt_line.bright_green(),
                        IpProto::Udp => pkt_line.bright_yellow(),
                        _ => {
                            continue;
                        }
                    };
                    println!("{output}");
                }
                /* handler something */
            }
        }
    }

    fn fork_tx(&self) -> mpsc::Sender<FlowPacket> {
        self.tx.clone()
    }
}
