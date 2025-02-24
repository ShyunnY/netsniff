use std::{collections::HashMap, time::Duration};

use chrono::Local;

use crate::{filter::convert_identity_map, metrics};

type DataMap = tokio::sync::RwLock<HashMap<String, PacketMetrics>>;

/// MetricsExporter exports network packets into metrics
pub struct MetricsExporter {
    // TODO: Maybe we can do it lock-free?
    packet_data: DataMap,
}

#[derive(Debug)]
struct PacketMetrics {
    data_totol: u64,
}

impl PacketMetrics {
    pub fn new() -> Self {
        Self { data_totol: 0 }
    }

    pub fn inc(&mut self, tol: u16) {
        self.data_totol += tol as u64;
    }

    pub fn get(&self) -> u64 {
        self.data_totol
    }
}

impl MetricsExporter {
    pub fn new() -> Self {
        Self {
            packet_data: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    pub async fn insert(&mut self, name: String) {
        let mut guard = self.packet_data.write().await;
        (*guard).insert(name, PacketMetrics::new());
    }

    pub async fn add(&self, name: &String, data_tol: u16) {
        let mut guard = self.packet_data.write().await;
        match (*guard).get_mut(name) {
            Some(pm) => {
                pm.inc(data_tol);
            }
            None => {}
        }
    }

    pub async fn flush(&self) {
        // TODO: need a more granular data export?
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            println!("tick! now = {}", Local::now().format("[%Y-%m-%d %H:%M:%S]"));
            let guard = self.packet_data.read().await;
            (*guard).iter().for_each(|(line, item)| {
                let meta_kvs = convert_identity_map(&line).unwrap();
                metrics::set_gauge(item.get() as i64, &meta_kvs);
            });

            metrics::export();
        }
    }
}
