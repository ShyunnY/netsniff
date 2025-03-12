use std::{collections::HashMap, path::Path};

use anyhow::Result;
use axum::{
    body::Body,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing, Router,
};
use log::{error, info};
use prometheus::{IntCounterVec, Opts, TextEncoder};
use tokio::{
    fs::File,
    io::{AsyncWriteExt, BufWriter},
    net::TcpListener,
};

static mut PACKET_TOL: Option<Box<IntCounterVec>> = None;

pub const PACKET_TOL_LV_CAP: usize = 5;

#[allow(static_mut_refs)]
pub fn build_metrics(const_lables: Vec<String>) -> Result<()> {
    let mut lable_names = vec!["rule_name", "traffic", "protocol", "network_iface", "port"];
    const_lables.iter().for_each(|v| {
        lable_names.push(v);
    });

    let counter = Box::new(IntCounterVec::new(
        Opts::new(
            "network_packet_tolal",
            "record the size of incoming and outgoing network packets",
        ),
        &lable_names,
    )?);

    prometheus::register(counter.clone())?;
    unsafe {
        PACKET_TOL = Some(counter);
    };
    info!(r"success to build metrics instance: 'network_packet_tolal'");
    Ok(())
}

#[allow(static_mut_refs)]
pub fn set_counter(val: u64, label_values: &HashMap<&str, &str>) {
    let counter = unsafe {
        if PACKET_TOL.is_none() {
            error!("network_packet_tolal metrics have not been initialized");
            return;
        }

        PACKET_TOL.as_ref().unwrap()
    };
    counter.with(label_values).inc_by(val);
}

pub async fn flush_file(path: impl AsRef<Path>) {
    let enc = TextEncoder::new();
    let mf = prometheus::gather();

    let output_f = File::options()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .await
        .unwrap();
    let mut buf = BufWriter::with_capacity(1024 * 1024, output_f);

    match enc.encode_to_string(&mf) {
        Ok(output_line) => {
            if let Err(e) = buf.write_all(output_line.as_bytes()).await {
                error!("failed to write metrics data to file by err {}", e);
                return;
            }
            buf.flush().await.unwrap();
        }
        Err(e) => error!("failed to encode prometheus metrics gather by err {}", e),
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
