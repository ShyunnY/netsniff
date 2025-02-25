use std::{collections::HashMap, time::Duration};

use crate::{filter::convert_identity_map, metrics};

type DataMap = tokio::sync::RwLock<HashMap<String, PacketCollector>>;

/// Collects the network packet size for each rule
pub struct CollectorMap {
    packet_data: DataMap,
}

struct PacketCollector {
    data_totol: u64,
}

impl PacketCollector {
    pub fn new() -> Self {
        Self { data_totol: 0 }
    }

    pub fn inc(&mut self, data_tol: u16) {
        self.data_totol += data_tol as u64;
    }

    pub fn clear(&mut self) {
        self.data_totol = 0;
    }

    pub fn get(&self) -> u64 {
        self.data_totol
    }
}

impl CollectorMap {
    pub fn new() -> Self {
        Self {
            packet_data: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    pub async fn insert(&mut self, name: String) {
        let mut guard = self.packet_data.write().await;
        (*guard).insert(name, PacketCollector::new());
    }

    pub async fn add(&self, name: &String, data_tol: u16) {
        let mut guard = self.packet_data.write().await;
        if let Some(c) = (*guard).get_mut(name) {
            c.inc(data_tol);
        }
    }

    pub async fn flush(&self) {
        // TODO: interval should be configurable
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        loop {
            tick.tick().await;

            let mut guard = self.packet_data.write().await;
            (*guard).iter_mut().for_each(|(line, item)| {
                let meta_kvs = convert_identity_map(&line).unwrap();
                metrics::set_gauge(item.get() as i64, &meta_kvs);

                item.clear();
            });
        }
    }
}
