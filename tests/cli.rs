//! End-to-end tests that run the real binary against a local origin server.
//!
//! These check the parts that only exist once a child process is involved: environment
//! injection, exit-code passthrough, and the shape of the emitted report.

use std::net::SocketAddr;
use std::process::Stdio;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_wiretally");

/// Starts an origin server that answers any request with a fixed-size body.
async fn http_origin(body_len: usize) -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                if stream.read(&mut buf).await.unwrap_or(0) == 0 {
                    return;
                }
                let body = "x".repeat(body_len);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {body_len}\r\nConnection: close\r\n\r\n{body}"
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

/// Set this to run the suite on a machine without `curl`, accepting the loss of coverage.
const OPT_OUT: &str = "WIRETALLY_ALLOW_MISSING_CURL";

/// Whether `curl` is on PATH; these tests use it as a stand-in for any proxy-aware client.
async fn have_curl() -> bool {
    Command::new("curl")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .is_ok_and(|status| status.success())
}

/// Whether to skip a test that needs `curl`, failing instead unless skipping was asked for.
///
/// A missing client used to make these tests return early and report success, which is the worst
/// of both worlds: no end-to-end coverage, and a green suite that hides it. Now the default is a
/// failure that names the cause, and skipping is a deliberate opt-in.
///
/// # Panics
///
/// Panics if `curl` is absent and [`OPT_OUT`] is not set.
async fn skip_without_curl() -> bool {
    if have_curl().await {
        return false;
    }
    assert!(
        std::env::var_os(OPT_OUT).is_some(),
        "curl is not on PATH, so this end-to-end test cannot run. Install curl, or set {OPT_OUT}=1 \
         to skip these tests and give up their coverage."
    );
    eprintln!("WARNING: skipping end-to-end test: curl is not on PATH and {OPT_OUT} is set");
    true
}

#[tokio::test]
async fn json_report_describes_traffic_from_a_real_client() {
    if skip_without_curl().await {
        return;
    }
    let origin = http_origin(4096).await;

    let output = Command::new(BIN)
        // No --domain-prefix: the loopback endpoint's reported name depends on whatever PTR
        // record this machine has for 127.0.0.1, which is not portable to assert on.
        .args(["--json", "--"])
        .args([
            "curl",
            "-s",
            "-o",
            "/dev/null",
            &format!("http://{origin}/blob"),
        ])
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "wiretally failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "stdout was not JSON ({err}): {:?}",
            String::from_utf8_lossy(&output.stdout)
        )
    });

    assert_eq!(report["exit_code"], 0);
    assert!(report["domain_prefix_filter"].is_null());
    assert_eq!(
        report["endpoints"].as_array().map(Vec::len),
        Some(1),
        "one origin was contacted: {report}"
    );
    let endpoint = &report["endpoints"][0];
    assert_eq!(endpoint["ip_address"], "127.0.0.1");
    assert_eq!(endpoint["matches_filter"], true);
    assert_eq!(endpoint["connections"], 1);
    assert!(
        endpoint["ingress_bytes"].as_u64().unwrap() >= 4096,
        "ingress should cover the 4 KiB body plus headers, got {endpoint}"
    );
    assert!(endpoint["egress_bytes"].as_u64().unwrap() > 0);
    assert_eq!(
        report["totals"]["matching_filter"]["ingress_bytes"],
        report["totals"]["all_destinations"]["ingress_bytes"],
        "with no filter, both totals rows agree"
    );
}

#[tokio::test]
async fn text_report_is_printed_and_exit_code_passes_through() {
    let output = Command::new(BIN)
        .args(["--", "sh", "-c", "exit 7"])
        .output()
        .await
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(7),
        "child exit code must propagate"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("WIRETALLY TRAFFIC SUMMARY"));
    assert!(stdout.contains("(no matching traffic observed)"));
}

#[tokio::test]
async fn proxy_environment_is_visible_to_the_child() {
    let output = Command::new(BIN)
        .args(["--", "sh", "-c", "echo $HTTPS_PROXY $http_proxy $ALL_PROXY"])
        .output()
        .await
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let injected: Vec<&str> = stdout
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    assert_eq!(
        injected.len(),
        3,
        "all three variables should be set: {stdout}"
    );
    let [https, http, all] = <[&str; 3]>::try_from(injected.as_slice()).unwrap();
    assert!(
        https.starts_with("http://127.0.0.1:") && http == https,
        "HTTP(S) clients get the CONNECT proxy: {injected:?}"
    );
    assert!(
        all.starts_with("socks5h://127.0.0.1:"),
        "ALL_PROXY advertises SOCKS5 so non-HTTP TCP is covered too: {injected:?}"
    );
    assert_eq!(
        all.rsplit(':').next(),
        https.rsplit(':').next(),
        "both protocols live on one port: {injected:?}"
    );
}

#[tokio::test]
async fn missing_command_is_an_error() {
    let output = Command::new(BIN).output().await.unwrap();
    assert!(!output.status.success());
}
