use std::collections::HashMap;

use anyhow::Result;
use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing, Router,
};
use log::info;
use prometheus::{IntGaugeVec, Opts, TextEncoder};
use tokio::net::TcpListener;

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

/// Sniff's metrics server has the following two functions:
/// 
/// 1. Provide a health check endpoint to report that the service is normal(`/-/health`)
/// 2. Provide a metrics capture endpoint(`/metrics`)
pub async fn metrics_server() {
    let app = Router::new()
        .route("/-/health", routing::get(health_handler))
        .route("/metrics", routing::get(metrics_handler));

    let listener = TcpListener::bind("127.0.0.1:10010").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

/// Collect all registered prometheus metrics and export them to be crawlable
async fn metrics_handler() -> Response {
    let enc = TextEncoder::new();
    let mf = prometheus::gather();

    let resp_bld = Response::builder();
    match enc.encode_to_string(&mf) {
        Ok(output) => Response::builder()
            .status(StatusCode::OK)
            .body(Body::from(output))
            .unwrap(),
        Err(e) => {
            let msg = format!("failed to encode metrics by err {}", e);
            resp_bld
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(msg))
                .unwrap()
        }
    }
}

async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "health\n")
}
