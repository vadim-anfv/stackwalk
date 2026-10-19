//! Prometheus metrics: compile requests by input kind and status, and the time they take.
//! Served by `api::metrics_router` on its own listener (`METRICS_BIND`), never on the
//! public one. Whether the service is up is Prometheus's own `up` for the scrape.
use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Default)]
pub struct Metrics(Mutex<Counts>);

#[derive(Default)]
struct Counts {
    /// (kind, HTTP status) -> requests; kind is one of a fixed set, never client text
    requests: BTreeMap<(&'static str, u16), u64>,
    seconds: f64,
    answered: u64,
}

impl Metrics {
    pub fn record(&self, kind: &'static str, status: u16, took: Duration) {
        let mut c = self.0.lock().unwrap_or_else(|e| e.into_inner());
        *c.requests.entry((kind, status)).or_default() += 1;
        c.seconds += took.as_secs_f64();
        c.answered += 1;
    }

    /// The Prometheus text format.
    pub fn render(&self) -> String {
        let c = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = String::new();
        out += "# HELP stackwalk_requests_total Compile requests by input kind and HTTP status.\n";
        out += "# TYPE stackwalk_requests_total counter\n";
        for ((kind, status), n) in &c.requests {
            let _ = writeln!(out, "stackwalk_requests_total{{kind=\"{kind}\",status=\"{status}\"}} {n}");
        }
        out += "# HELP stackwalk_compile_seconds Time to answer a compile request.\n";
        out += "# TYPE stackwalk_compile_seconds summary\n";
        let _ = writeln!(out, "stackwalk_compile_seconds_sum {}", c.seconds);
        let _ = writeln!(out, "stackwalk_compile_seconds_count {}", c.answered);
        out
    }
}
