use std::{net::IpAddr, sync::Arc};

use colored::Colorize;
use log::info;
use network_types::ip::IpProto;
use sniff_common::Flow;
use tokio::sync::mpsc;

use crate::{cidr::PrefixTree, ebpf, filter::Filter, network::NetworkPacket, util};

pub struct Application {
    pub ifaces: Vec<String>,
    pub trie: PrefixTree<Arc<Box<Filter>>>,

    pub empty_filter: Option<Vec<Arc<Box<Filter>>>>,
    pub rx: mpsc::Receiver<NetworkPacket>,
    pub tx: mpsc::Sender<NetworkPacket>,
}

impl Application {
    pub fn new(
        ifaces: Vec<String>,
        trie: PrefixTree<Arc<Box<Filter>>>,
        empty_filter: Option<Vec<Arc<Box<Filter>>>>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(4096 * 4096);
        Self {
            ifaces,
            trie,
            rx,
            tx,
            empty_filter,
        }
    }

    pub async fn run(&mut self, proto: i32, flow: Flow) {
        info!(
            "start sniff traffic process, flow: {:?}, kernal: {:?}",
            flow,
            util::uname().unwrap().release,
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
            if let Some(net_pkt) = self.rx.recv().await {
                let addr = match net_pkt.flow {
                    Flow::Ingress => net_pkt.pkt.src_ip,
                    Flow::Egress => net_pkt.pkt.dst_ip,
                    Flow::All => {
                        /* this branch should not be executed */
                        continue;
                    }
                };

                let exist = if !self.trie.empty() {
                    let (exist, filter) = self.trie.search(IpAddr::V4(addr));
                    if exist {
                        println!("filter!");
                        /* todo: do something */
                        filter.filter(&net_pkt);
                    }

                    exist
                } else {
                    false
                };

                // regardless of whether it exists, we need to further match it accurately
                if !exist {
                    println!("{:?}", self.empty_filter);
                    if let Some(empty_filter) = &self.empty_filter {
                        for f in empty_filter {
                            let (ok, _) = f.filter(&net_pkt);
                            if ok {
                                println!("empty filter match!");
                                break;
                            }
                        }
                    }
                }

                if log::log_enabled!(log::Level::Debug) {
                    let pkt_line = String::from(format!("{}", net_pkt));
                    let output = match net_pkt.pkt.proto {
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

    fn fork_tx(&self) -> mpsc::Sender<NetworkPacket> {
        self.tx.clone()
    }
}
