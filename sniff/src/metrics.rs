use std::collections::HashMap;

use anyhow::{Ok, Result};
use log::info;
use prometheus::{IntGaugeVec, Opts};

static mut PACKET_TOL: Option<HashMap<String, Box<IntGaugeVec>>> = None;

pub const PACKET_TOL_LV_CAP: usize = 5;

#[allow(static_mut_refs)]
pub fn build_metrics(name: &String, label_values: &HashMap<String, String>) -> Result<()> {
    let m = unsafe {
        if PACKET_TOL.is_none() {
            PACKET_TOL = Some(HashMap::new());
        }

        PACKET_TOL.as_mut().unwrap()
    };

    let gauge = Box::new(IntGaugeVec::new(
        Opts::new(
            "network_packet_tolal",
            "record the size of incoming and outgoing network packets",
        )
        .const_labels(label_values.clone()),
        &["rule_name", "traffic", "protocol", "network_iface", "port"],
    )?);
    prometheus::register(gauge.clone())?;
    m.insert(name.to_owned(), gauge);
    info!("success to build '{}' metrics", name);

    Ok(())
}

#[allow(static_mut_refs)]
pub fn set_gauge(val: i64, label_values: &HashMap<&str, &str>) {
    let metrics_map = unsafe {
        if PACKET_TOL.is_none() {
            return;
        }

        PACKET_TOL.as_ref().unwrap()
    };

    let name = label_values.get("rule_name").unwrap().to_string();
    if let Some(gauge) = metrics_map.get(&name) {
        gauge.with(&label_values).set(val);
    }
}
