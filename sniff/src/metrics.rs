use std::collections::HashMap;

use anyhow::Result;
use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing, Router,
};
use log::{error, info};
use prometheus::{IntGaugeVec, Opts, TextEncoder};
use tokio::net::TcpListener;

static mut PACKET_TOL: Option<Box<IntGaugeVec>> = None;

pub const PACKET_TOL_LV_CAP: usize = 5;

#[allow(static_mut_refs)]
pub fn build_metrics(const_lables: Vec<String>) -> Result<()> {
    let mut lable_names = vec![
        "rule_name",
        "traffic",
        "protocol",
        "network_iface",
        "port",
    ];
    const_lables.iter().for_each(|v| {
        lable_names.push(v);
    });

    let gauge = Box::new(IntGaugeVec::new(
        Opts::new(
            "network_packet_tolal",
            "record the size of incoming and outgoing network packets",
        ),
        &lable_names,
    )?);

    prometheus::register(gauge.clone())?;
    unsafe {
        PACKET_TOL = Some(gauge);
    };
    info!(r"success to build metrics instance: 'network_packet_tolal'");
    Ok(())
}

#[allow(static_mut_refs)]
pub fn set_gauge(val: i64, label_values: &HashMap<&str, &str>) {
    let gauge = unsafe {
        if PACKET_TOL.is_none() {
            error!("network_packet_tolal metrics have not been initialized");
            return;
        }

        PACKET_TOL.as_ref().unwrap()
    };
    gauge.with(&label_values).set(val);
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
