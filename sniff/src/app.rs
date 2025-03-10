use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use colored::Colorize;
use log::{info, trace};
use sniff_common::Flow;
use tokio::sync::mpsc;

use crate::{
    cidr::PrefixTree,
    collector::{self, CollectorMap},
    ebpf,
    filter::Filter,
    metrics,
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
        let collector = collector.map(Arc::new);

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

        self.startup_collector().await;
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
                    self.record_collector(&filter.rule_name(), net_pkt, filter.enable_port())
                        .await;
                    self.log_packet(net_pkt);
                }
            }
        } else if let Some(empty_filter) = &self.empty_filter {
            for filter in empty_filter {
                let (ok, _) = filter.filter(net_pkt);
                if ok {
                    self.log_packet(net_pkt);
                    break;
                }
            }
        } else if self.trie.match_all() {
            self.log_packet(net_pkt);
        }
    }

    /// Output logs in different colors according to traffic direction
    fn log_packet(&self, net_pkt: &NetworkPacket) {
        if log::log_enabled!(log::Level::Debug) {
            let pkt_line = format!("{}", net_pkt);
            let output = match net_pkt.flow {
                Flow::Ingress => pkt_line.bright_green(),
                Flow::Egress => pkt_line.bright_yellow(),
                _ => return,
            };
            trace!("{output}");
        }
    }

    /// record packet information to collector, if set
    async fn record_collector(
        &self,
        rule_name: &String,
        net_pkt: &NetworkPacket,
        enable_port: bool,
    ) {
        if let Some(collector) = &self.collector {
            let identity = collector::netpkt_to_identity(rule_name, enable_port, net_pkt);
            collector.add(&identity, net_pkt.pkt.length);
        }
    }

    /// Start the collector, which will periodically flush network packets to metrics.
    ///
    /// At the same time, starting the collector means starting a metrics server to help the program expose metrics
    async fn startup_collector(&mut self) {
        if let Some(collector) = &self.collector {
            let clone = collector.clone();
            tokio::spawn(async move {
                clone.flush().await;
            });
            tokio::spawn(async {
                metrics::metrics_server().await;
            });
        }
    }

    fn fork_tx(&self) -> mpsc::Sender<NetworkPacket> {
        self.tx.clone()
    }
}
