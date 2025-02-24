use std::collections::HashMap;

use log::info;
use prometheus::{IntGaugeVec, Opts, TextEncoder};

static mut PACKET_TOL: Option<HashMap<String, Box<IntGaugeVec>>> = None;

// todo: handler err handler
#[allow(static_mut_refs)]
pub fn build_metrics(name: &String, label_values: &HashMap<String, String>) {
    unsafe {
        if PACKET_TOL.is_none() {
            PACKET_TOL = Some(HashMap::new());
        }

        let m = PACKET_TOL.as_mut().unwrap();
        let gauge = Box::new(
            IntGaugeVec::new(
                Opts::new(
                    "packet_tol",
                    "record the size of incoming and outgoing packets",
                )
                .const_labels(label_values.clone()),
                &["rule_name", "traffic", "iface", "port"],
            )
            .unwrap(),
        );
        prometheus::register(gauge.clone()).unwrap();
        m.insert(name.to_owned(), gauge);

        info!("success to build '{}' metrics", name)
    }
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

pub fn export() {
    let text_enc = TextEncoder::new();
    let mf = prometheus::gather();
    println!("{}", text_enc.encode_to_string(&mf).unwrap());
}
