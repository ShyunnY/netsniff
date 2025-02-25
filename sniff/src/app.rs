use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use colored::Colorize;
use log::info;
use sniff_common::Flow;
use tokio::sync::mpsc;

use crate::{
    cidr::PrefixTree,
    collector::CollectorMap,
    ebpf,
    filter::{convert_line_identity, Filter},
    network::NetworkPacket,
    util,
};

pub struct Application {
    pub ifaces: Vec<String>,

    pub trie: PrefixTree<Arc<Box<Filter>>>,
    pub empty_filter: Option<Vec<Arc<Box<Filter>>>>,

    pub rx: mpsc::Receiver<NetworkPacket>,
    pub tx: mpsc::Sender<NetworkPacket>,

    pub collector: Option<Arc<CollectorMap>>,
}

impl Application {
    pub fn new(
        ifaces: Vec<String>,
        trie: PrefixTree<Arc<Box<Filter>>>,
        empty_filter: Option<Vec<Arc<Box<Filter>>>>,
        collector: Option<CollectorMap>,
    ) -> Self {
        let (tx, rx) = mpsc::channel(4096 * 4096);
        let collector = if let Some(exp) = collector {
            Some(Arc::new(exp))
        } else {
            None
        };

        Self {
            ifaces,
            trie,
            rx,
            tx,
            empty_filter,
            collector,
        }
    }

    pub async fn run(&mut self, proto: i32, flow: Flow) {
        info!(
            "start sniff traffic process, flow: {:?}, kernel: {:?}",
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

        self.startup_exporter().await;
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

                /* handler something */
                self.search_and_filter(addr, &net_pkt).await;
            }
        }
    }

    #[inline]
    async fn search_and_filter(&self, addr: Ipv4Addr, net_pkt: &NetworkPacket) {
        if !self.trie.empty() {
            let (exit, filter) = self.trie.search(IpAddr::V4(addr));
            if exit {
                let (ok, _) = filter.filter(net_pkt);
                if ok {
                    self.record_exporter(&filter.rule_name(), net_pkt, filter.enable_port())
                        .await;
                    self.log_packet(&net_pkt);
                }
            }
        } else if let Some(empty_filter) = &self.empty_filter {
            for filter in empty_filter {
                let (ok, _) = filter.filter(&net_pkt);
                if ok {
                    self.log_packet(&net_pkt);
                    break;
                }
            }
        }
    }

    /// Output logs in different colors according to traffic direction
    fn log_packet(&self, net_pkt: &NetworkPacket) {
        if log::log_enabled!(log::Level::Debug) {
            let pkt_line = String::from(format!("{}", net_pkt));
            let output = match net_pkt.flow {
                Flow::Ingress => pkt_line.bright_green(),
                Flow::Egress => pkt_line.bright_yellow(),
                _ => return,
            };
            println!("{output}");
        }
    }

    /// record packet information to exporter, if set
    async fn record_exporter(&self, name: &String, net_pkt: &NetworkPacket, has_port: bool) {
        if let Some(exporter) = &self.collector {
            let identity = convert_line_identity(net_pkt.flow, name, &net_pkt.iface, {
                if has_port {
                    net_pkt.pkt.dst.to_string()
                } else {
                    "undefine".to_string()
                }
            });
            exporter.add(&identity, net_pkt.pkt.length).await
        }
    }

    async fn startup_exporter(&mut self) {
        if let Some(exporter) = &self.collector {
            let clone = exporter.clone();
            tokio::spawn(async move {
                clone.flush().await;
            });
        }
    }

    fn fork_tx(&self) -> mpsc::Sender<NetworkPacket> {
        self.tx.clone()
    }
}
