//! Final summary rendering, in both human and JSON form.

use std::fmt::Write as _;

use serde::Serialize;

use crate::stats::Endpoint;

/// Width of the rules in the text report.
const RULE: usize = 80;
/// Width of the endpoint column; longer names are elided.
const DOMAIN_COL: usize = 34;

/// Aggregate byte and connection counts for a group of endpoints.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Totals {
    /// Bytes received across the group.
    pub ingress_bytes: u64,
    /// Bytes sent across the group.
    pub egress_bytes: u64,
    /// Connections opened across the group.
    pub connections: u64,
}

impl Totals {
    /// Sums the counters of every endpoint in `endpoints`.
    pub fn of<'a>(endpoints: impl IntoIterator<Item = &'a Endpoint>) -> Self {
        endpoints
            .into_iter()
            .fold(Self::default(), |mut acc, endpoint| {
                acc.ingress_bytes += endpoint.ingress_bytes;
                acc.egress_bytes += endpoint.egress_bytes;
                acc.connections += endpoint.connections;
                acc
            })
    }
}

/// Both totals rows of the report.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct TotalsBreakdown {
    /// Totals restricted to endpoints matching the domain filter.
    pub matching_filter: Totals,
    /// Totals across every endpoint the child touched.
    pub all_destinations: Totals,
}

/// A complete run summary, ready to render as text or JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// The child command line as invoked.
    pub command: String,
    /// The `--domain-prefix` value, if one was given.
    pub domain_prefix_filter: Option<String>,
    /// Wall-clock duration of the child process.
    pub execution_time_ms: u128,
    /// Exit status of the child process.
    pub exit_code: i32,
    /// Filtered and unfiltered totals.
    pub totals: TotalsBreakdown,
    /// Per-endpoint detail, ordered by ingress bytes descending.
    pub endpoints: Vec<Endpoint>,
}

impl Report {
    /// Builds a report from a registry snapshot.
    pub fn new(
        command: String,
        domain_prefix_filter: Option<String>,
        execution_time_ms: u128,
        exit_code: i32,
        endpoints: Vec<Endpoint>,
    ) -> Self {
        let totals = TotalsBreakdown {
            matching_filter: Totals::of(endpoints.iter().filter(|e| e.matches_filter)),
            all_destinations: Totals::of(endpoints.iter()),
        };
        Self {
            command,
            domain_prefix_filter,
            execution_time_ms,
            exit_code,
            totals,
            endpoints,
        }
    }

    /// Serializes the report as pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns an error only if serialization itself fails, which cannot happen for this type
    /// in practice.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }

    /// Renders the human-readable summary table.
    ///
    /// Endpoints that do not match the domain filter are omitted from the table but still
    /// contribute to the "all destinations" totals, so filtering never hides traffic entirely.
    pub fn to_text(&self) -> String {
        let rule = "=".repeat(RULE);
        let thin = "-".repeat(RULE);
        let mut out = String::with_capacity(1024);

        let _ = writeln!(out, "{rule}");
        let _ = writeln!(
            out,
            "{:^width$}",
            "NET-COUNTER TRAFFIC SUMMARY",
            width = RULE
        );
        let _ = writeln!(out, "{rule}");
        let _ = writeln!(out, "Command:          {}", self.command);
        let filter = match &self.domain_prefix_filter {
            Some(prefix) => format!("*.{prefix} (Prefix Match)"),
            None => "none (all destinations)".to_owned(),
        };
        let _ = writeln!(out, "Target Filter:    {filter}");
        let _ = writeln!(
            out,
            "Execution Time:   {:.2}s",
            self.execution_time_ms as f64 / 1000.0
        );
        let _ = writeln!(out, "Exit Code:        {}", self.exit_code);
        let _ = writeln!(out);
        let _ = writeln!(out, "DOMAIN / ENDPOINT SUMMARY:");
        let _ = writeln!(out, "{thin}");
        let _ = writeln!(
            out,
            "{:<DOMAIN_COL$}{:>14}{:>17}{:>8}",
            "ENDPOINT / DOMAIN", "INGRESS (Rx)", "EGRESS (Tx)", "CONNS"
        );
        let _ = writeln!(out, "{thin}");

        let shown: Vec<&Endpoint> = self
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.matches_filter)
            .collect();
        if shown.is_empty() {
            let _ = writeln!(out, "(no matching traffic observed)");
        }
        for endpoint in shown {
            let _ = writeln!(
                out,
                "{:<DOMAIN_COL$}{:>14}{:>17}{:>8}",
                elide(&endpoint.domain, DOMAIN_COL - 1),
                format_bytes(endpoint.ingress_bytes),
                format_bytes(endpoint.egress_bytes),
                endpoint.connections
            );
        }

        let _ = writeln!(out, "{thin}");
        for (label, totals) in [
            ("TOTAL (Matching Filter):", self.totals.matching_filter),
            ("TOTAL (All Destinations):", self.totals.all_destinations),
        ] {
            let _ = writeln!(
                out,
                "{:<DOMAIN_COL$}{:>14}{:>17}{:>8}",
                label,
                format_bytes(totals.ingress_bytes),
                format_bytes(totals.egress_bytes),
                totals.connections
            );
        }
        let _ = writeln!(out, "{rule}");
        out
    }
}

/// Formats a byte count with binary units, two decimals above the kilobyte.
///
/// ```
/// use net_counter::report::format_bytes;
///
/// assert_eq!(format_bytes(512), "512 B");
/// assert_eq!(format_bytes(4311), "4.21 KB");
/// assert_eq!(format_bytes(149_760_000), "142.82 MB");
/// ```
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KB", "MB", "GB", "TB", "PB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = UNITS[0];
    for next in &UNITS[1..] {
        if value < 1024.0 {
            break;
        }
        value /= 1024.0;
        unit = next;
    }
    format!("{value:.2} {unit}")
}

/// Truncates `text` to `max` characters, marking the cut with an ellipsis.
fn elide(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_owned();
    }
    let kept: String = text.chars().take(max.saturating_sub(1)).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(domain: &str, rx: u64, tx: u64, conns: u64, matches: bool) -> Endpoint {
        Endpoint {
            domain: domain.to_owned(),
            ip_address: Some("10.0.0.1".parse().unwrap()),
            ingress_bytes: rx,
            egress_bytes: tx,
            connections: conns,
            matches_filter: matches,
        }
    }

    #[test]
    fn byte_formatting_matches_spec_examples() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(4311), "4.21 KB");
        assert_eq!(format_bytes(149_760_000), "142.82 MB");
        assert_eq!(format_bytes(2 * 1024 * 1024 * 1024), "2.00 GB");
    }

    #[test]
    fn totals_split_filtered_from_all() {
        let report = Report::new(
            "curl x".to_owned(),
            Some("example.com".to_owned()),
            1840,
            0,
            vec![
                endpoint("a.example.com", 100, 10, 2, true),
                endpoint("other.dev", 5, 1, 1, false),
            ],
        );
        assert_eq!(report.totals.matching_filter.ingress_bytes, 100);
        assert_eq!(report.totals.all_destinations.ingress_bytes, 105);
        assert_eq!(report.totals.all_destinations.connections, 3);
    }

    #[test]
    fn text_report_hides_nonmatching_rows_but_keeps_them_in_totals() {
        let report = Report::new(
            "curl x".to_owned(),
            Some("example.com".to_owned()),
            1000,
            0,
            vec![
                endpoint("a.example.com", 100, 10, 1, true),
                endpoint("other.dev", 5, 1, 1, false),
            ],
        );
        let text = report.to_text();
        assert!(text.contains("a.example.com"));
        assert!(!text.contains("other.dev"));
        assert!(text.contains("TOTAL (All Destinations):"));
        assert!(text.lines().all(|line| line.chars().count() <= RULE + 4));
    }

    #[test]
    fn json_uses_the_specified_field_names() {
        let report = Report::new(
            "mcap info".to_owned(),
            Some("amazonaws.com".to_owned()),
            1840,
            0,
            vec![endpoint(
                "s3.amazonaws.com",
                149_760_000,
                1_174_405,
                8,
                true,
            )],
        );
        let json: serde_json::Value = serde_json::from_str(&report.to_json().unwrap()).unwrap();
        assert_eq!(json["domain_prefix_filter"], "amazonaws.com");
        assert_eq!(json["execution_time_ms"], 1840);
        assert_eq!(
            json["totals"]["matching_filter"]["ingress_bytes"],
            149_760_000
        );
        assert_eq!(json["endpoints"][0]["ip_address"], "10.0.0.1");
        assert_eq!(json["endpoints"][0]["matches_filter"], true);
    }

    #[test]
    fn elide_keeps_column_width() {
        let long = "a".repeat(60);
        assert_eq!(elide(&long, 10).chars().count(), 10);
        assert_eq!(elide("short", 10), "short");
    }
}
