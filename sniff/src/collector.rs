use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use network_types::ip::IpProto;
use sniff_common::Flow;

use crate::{
    filter::Filter,
    metrics,
    network::{NetworkPacket, Proto},
};

type DataMap = HashMap<String, PacketCollector>;

/// Collects the network packet size for each rule
pub struct CollectorMap {
    packet_data: DataMap,
}

struct PacketCollector {
    data_total: AtomicU64,
    label_values: Option<Arc<HashMap<String, String>>>,
}

impl PacketCollector {
    pub fn new(label_values: Option<Arc<HashMap<String, String>>>) -> Self {
        Self {
            data_total: AtomicU64::new(0),
            label_values,
        }
    }

    pub fn set(&self, data_tol: u16) {
        // "Acquire" is used here to avoid reordering subsequent operations.
        let val = self.data_total.load(Ordering::Acquire);
        self.data_total
            .store(val + (data_tol as u64), Ordering::Relaxed);
    }

    pub fn clear(&self) {
        self.data_total.store(0, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.data_total.load(Ordering::Relaxed)
    }
}

impl CollectorMap {
    pub fn new() -> Self {
        Self {
            packet_data: HashMap::new(),
        }
    }

    pub fn insert(&mut self, name: String, label_values: Option<Arc<HashMap<String, String>>>) {
        self.packet_data
            .insert(name, PacketCollector::new(label_values));
    }

    pub fn add(&self, name: &String, data_tol: u16) {
        if let Some(c) = self.packet_data.get(name) {
            c.set(data_tol);
        }
    }

    pub async fn flush(&self) {
        // TODO: interval should be configurable
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;

            self.packet_data.iter().for_each(|(identity_line, item)| {
                let mut meta_kvs = identity_to_label_values(&identity_line);
                let metadata = if let Some(metadata) = &item.label_values {
                    serde_json::to_string(&**metadata).unwrap()
                } else {
                    String::from("unset")
                };
                meta_kvs.insert("metadata", &metadata);

                metrics::set_gauge(item.get() as i64, &meta_kvs);
                item.clear();
            });
        }
    }
}

pub fn identity_to_label_values<'a>(identity_line: &'a String) -> HashMap<&'a str, &'a str> {
    let values: Vec<&str> = identity_line.split("_").collect();
    let mut result = HashMap::with_capacity(metrics::PACKET_TOL_LV_CAP);

    result.insert("rule_name", values[0]);
    result.insert("traffic", values[1]);
    result.insert("protocol", values[2]);
    result.insert("network_iface", values[3]);
    result.insert("port", values[4]);

    result
}

/// Converts a [NetworkPacket] to an Identity unique identifier.
///
/// This function is mainly used to find its [PacketCollector] in [Collector].
/// For more information, see [filter_to_identity]
pub fn netpkt_to_identity(
    rule_name: &String,
    enable_port: bool,
    net_pkt: &NetworkPacket,
) -> String {
    let (traffic, port) = match &net_pkt.flow {
        Flow::Ingress => ("ingress", {
            if enable_port {
                net_pkt.pkt.dst.to_string()
            } else {
                "undefine".to_string()
            }
        }),
        Flow::Egress => ("egress", "unsupport".to_string()),
        Flow::All => panic!("should be no bidirectional traffic type"),
    };

    let proto = match &net_pkt.pkt.proto {
        IpProto::Tcp => "tcp",
        IpProto::Udp => "udp",
        _ => panic!(
            "protocol is currently not supported: {:?}",
            &net_pkt.pkt.proto
        ),
    };

    format!(
        "{}_{}_{}_{}_{}",
        rule_name, traffic, proto, &net_pkt.iface, port
    )
}

/// Convert filter to Identity string identifier.
/// `rule_name`` is unique, so we can combine rule_name with traffic direction, protocol, port, etc. to form a unique identifier.
///
/// The unique identifier can offload a lot of metadata to find its associated [PacketCollector] in [Collector]
///
/// * format it follows is: `<rule_name>_<flow>_<protocol>_<iface>_<port>`
/// * final effect demo is as follows: `demo1_ingress_tcp_enp1s0_undefine`
pub fn filter_to_identity(filter: &Filter) -> Vec<String> {
    let mut identitys = Vec::new();

    let must_proto = match filter.protocol {
        Proto::TCP => vec!["tcp"],
        Proto::UDP => vec!["udp"],
        Proto::ALL => vec!["tcp", "udp"],
    };

    for iface in &filter.in_iface_filter {
        if filter.in_port_filter.len() > 0 {
            for port in &filter.in_port_filter {
                for proto in &must_proto {
                    identitys.push(format!(
                        "{}_{}_{}_{}_{}",
                        filter.rule_name(),
                        "ingress",
                        proto,
                        iface,
                        port
                    ));
                }
            }
        } else {
            for proto in &must_proto {
                identitys.push(format!(
                    "{}_{}_{}_{}_{}",
                    filter.rule_name(),
                    "ingress",
                    proto,
                    iface,
                    "undefine"
                ));
            }
        }
    }

    for iface in &filter.out_iface_filter {
        for proto in &must_proto {
            identitys.push(format!(
                "{}_{}_{}_{}_{}",
                filter.rule_name(),
                "egress",
                proto,
                iface,
                "unsupport",
            ));
        }
    }

    identitys
}
