//! Edge cases found by mutation testing: oversized unterminated lines and
//! clamping of the client-supplied wait time.
mod common;
use common::*;
use secret_proto::MAX_LINE_LEN;
use serde_json::json;
use std::time::{Duration, Instant};

#[tokio::test]
async fn flood_without_newline_is_cut_off() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    // More than the maximum line length and no newline at all: the server must
    // not buffer forever; it answers INVALID_REQUEST and closes.
    c.send_raw(&vec![b'a'; MAX_LINE_LEN + 4096]).await;
    let r = tokio::time::timeout(Duration::from_secs(5), c.recv())
        .await
        .expect("server did not react to an unterminated oversized line")
        .expect("expected an error response");
    assert_eq!(r.error.unwrap().code, -32600);
    assert!(c.recv().await.is_none(), "connection is closed afterwards");
}

#[tokio::test]
async fn terminated_oversized_line_is_rejected() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    let mut line = vec![b'a'; MAX_LINE_LEN + 10];
    line.push(b'\n');
    c.send_raw(&line).await;
    let r = c.recv().await.unwrap();
    assert_eq!(r.error.unwrap().code, -32600);
    assert!(c.recv().await.is_none());
}

#[tokio::test]
async fn timeout_secs_is_clamped_to_the_server_maximum() {
    let h = Harness::start(Opts {
        timeout_secs: 2,
        ..Opts::default()
    })
    .await;
    let mut c = h.connect().await;
    let t0 = Instant::now();
    c.send(
        "secret.get",
        json!({"name": "db-password", "timeout_secs": 3600}),
    )
    .await;
    let r = tokio::time::timeout(Duration::from_secs(6), c.recv())
        .await
        .expect("the 3600s request was not clamped to the 2s server maximum")
        .unwrap();
    assert_eq!(err_kind(&r), "TIMEOUT");
    let el = t0.elapsed();
    assert!(
        el >= Duration::from_millis(1800) && el < Duration::from_secs(4),
        "{el:?}"
    );
}

#[tokio::test]
async fn timeout_secs_has_a_one_second_floor() {
    let h = Harness::start(Opts::default()).await;
    let mut c = h.connect().await;
    let t0 = Instant::now();
    c.send(
        "secret.get",
        json!({"name": "db-password", "timeout_secs": 0}),
    )
    .await;
    let r = c.recv().await.unwrap();
    assert_eq!(err_kind(&r), "TIMEOUT");
    assert!(
        t0.elapsed() >= Duration::from_millis(900),
        "{:?}",
        t0.elapsed()
    );
}
