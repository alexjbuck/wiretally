//! `net-counter` — run a command behind an ephemeral counting proxy and report its traffic.

use std::ffi::OsString;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use net_counter::dns::ReverseResolver;
use net_counter::proxy::Proxy;
use net_counter::report::Report;
use net_counter::stats::Registry;
use tokio::process::Command;

/// How long to wait for in-flight tunnels to drain after the child exits.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
/// Poll interval used while draining.
const DRAIN_POLL: Duration = Duration::from_millis(10);

/// Measure the network traffic of a child process, grouped by remote domain.
#[derive(Debug, Parser)]
#[command(
    name = "net-counter",
    version,
    about = "Run a command behind a counting HTTP/HTTPS proxy and summarize its traffic",
    after_help = "Example:\n  net-counter --domain-prefix amazonaws.com -- curl -sO https://example.com/f"
)]
struct Cli {
    /// Domain suffix filter, e.g. "amazonaws.com"; groups matching traffic in the summary
    #[arg(short = 'd', long, value_name = "STRING")]
    domain_prefix: Option<String>,

    /// Log every connection and chunk of wire traffic to stderr
    #[arg(short, long)]
    verbose: bool,

    /// Emit the summary as JSON on stdout instead of a table
    #[arg(short, long)]
    json: bool,

    /// The command to run, after `--`
    #[arg(last = true, required = true, num_args = 1.., allow_hyphen_values = true, value_name = "COMMAND")]
    command: Vec<OsString>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("net-counter: {err:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let registry = Arc::new(Registry::new());
    let proxy = Proxy::bind(Arc::clone(&registry), cli.verbose).await?;
    let proxy_url = proxy.url();
    if cli.verbose {
        eprintln!("[net-counter] proxy listening on {proxy_url}");
    }

    let (program, args) = cli
        .command
        .split_first()
        .expect("clap guarantees at least one argument");
    let command_line = cli
        .command
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ");

    let mut child = {
        let mut command = Command::new(program);
        command.args(args);
        for key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            command.env(key, &proxy_url);
        }
        command.spawn().map_err(|err| {
            anyhow::anyhow!("failed to run `{}`: {err}", program.to_string_lossy())
        })?
    };

    let started = Instant::now();
    let status = child.wait().await?;
    let elapsed = started.elapsed();

    // Stop accepting new connections, then let whatever is still in flight finish so late
    // response bytes are not lost from the totals.
    drop(proxy);
    drain(&registry).await;

    resolve_ip_only_endpoints(&registry).await;

    let exit_code = exit_code(&status);
    let report = Report::new(
        command_line,
        cli.domain_prefix.clone(),
        elapsed.as_millis(),
        exit_code,
        registry.snapshot(cli.domain_prefix.as_deref()),
    );

    if cli.json {
        println!("{}", report.to_json()?);
    } else {
        print!("{}", report.to_text());
    }

    Ok(ExitCode::from(u8::try_from(exit_code).unwrap_or(1)))
}

/// Waits, up to [`DRAIN_TIMEOUT`], for open connections to close.
async fn drain(registry: &Registry) {
    let deadline = Instant::now() + DRAIN_TIMEOUT;
    while registry.open_connections() > 0 && Instant::now() < deadline {
        tokio::time::sleep(DRAIN_POLL).await;
    }
}

/// Replaces endpoint keys that are bare IP addresses with their PTR hostnames.
///
/// Endpoints reached by hostname are left untouched: the name the child asked for is more
/// meaningful than the reverse record of the address it landed on.
async fn resolve_ip_only_endpoints(registry: &Registry) {
    let ip_hosts: Vec<(String, std::net::IpAddr)> = registry
        .hosts()
        .into_iter()
        .filter_map(|(host, _)| host.parse().ok().map(|ip| (host, ip)))
        .collect();
    if ip_hosts.is_empty() {
        return;
    }

    let resolver = Arc::new(ReverseResolver::from_system());
    let handles: Vec<_> = ip_hosts
        .into_iter()
        .map(|(host, ip)| {
            let resolver = Arc::clone(&resolver);
            tokio::spawn(async move { (host, resolver.hostname(ip).await) })
        })
        .collect();
    for handle in handles {
        if let Ok((host, Some(name))) = handle.await {
            registry.rename(&host, &name);
        }
    }
}

/// Maps a child exit status onto a process exit code, using the shell's `128 + signal`
/// convention for signal deaths.
fn exit_code(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_requires_a_command_after_double_dash() {
        assert!(Cli::try_parse_from(["net-counter"]).is_err());
        let cli = Cli::try_parse_from([
            "net-counter",
            "-jv",
            "-d",
            "example.com",
            "--",
            "curl",
            "-s",
            "https://x",
        ])
        .expect("flags then command should parse");
        assert!(cli.json && cli.verbose);
        assert_eq!(cli.domain_prefix.as_deref(), Some("example.com"));
        assert_eq!(cli.command, ["curl", "-s", "https://x"]);
    }
}
