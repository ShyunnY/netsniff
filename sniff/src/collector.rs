use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use crate::{filter::convert_identity_map, metrics};

type DataMap = HashMap<String, PacketCollector>;

/// Collects the network packet size for each rule
pub struct CollectorMap {
    packet_data: DataMap,
}

struct PacketCollector {
    data_total: AtomicU64,
}

impl PacketCollector {
    pub fn new() -> Self {
        Self {
            data_total: AtomicU64::new(0),
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

    pub fn insert(&mut self, name: String) {
        self.packet_data.insert(name, PacketCollector::new());
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

            self.packet_data.iter().for_each(|(line, item)| {
                let meta_kvs = convert_identity_map(&line).unwrap();
                metrics::set_gauge(item.get() as i64, &meta_kvs);

                item.clear();
            });
        }
    }
}
