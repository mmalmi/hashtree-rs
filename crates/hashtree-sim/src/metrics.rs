//! Simulation metrics collection

use hdrhistogram::Histogram;

/// Collected metrics from simulation run
#[derive(Debug)]
pub struct SimMetrics {
    /// Total requests made
    pub total_requests: u64,

    /// Successful requests (data found)
    pub successful_requests: u64,

    /// Failed requests (data not found)
    pub failed_requests: u64,

    /// Requests that received wrong data (from malicious nodes)
    pub corrupted_responses: u64,

    /// Total messages sent across network
    pub total_messages: u64,

    /// Messages per successful request (bandwidth overhead)
    pub messages_per_success: f64,

    /// Latency histogram (milliseconds)
    latency_hist: Histogram<u64>,

    /// Hops histogram (how many forwards to find data)
    hops_hist: Histogram<u64>,

    /// Cache hit rate per node
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl SimMetrics {
    pub fn new() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            corrupted_responses: 0,
            total_messages: 0,
            messages_per_success: 0.0,
            latency_hist: Histogram::new(3).unwrap(),
            hops_hist: Histogram::new(2).unwrap(),
            cache_hits: 0,
            cache_misses: 0,
        }
    }

    pub fn record_request(&mut self, success: bool, corrupted: bool) {
        self.total_requests += 1;
        if success {
            self.successful_requests += 1;
        } else {
            self.failed_requests += 1;
        }
        if corrupted {
            self.corrupted_responses += 1;
        }
    }

    pub fn record_latency(&mut self, latency_ms: u64) {
        let _ = self.latency_hist.record(latency_ms);
    }

    pub fn record_hops(&mut self, hops: u32) {
        let _ = self.hops_hist.record(hops as u64);
    }

    pub fn record_message(&mut self) {
        self.total_messages += 1;
    }

    pub fn record_cache_hit(&mut self) {
        self.cache_hits += 1;
    }

    pub fn record_cache_miss(&mut self) {
        self.cache_misses += 1;
    }

    pub fn finalize(&mut self) {
        if self.successful_requests > 0 {
            self.messages_per_success =
                self.total_messages as f64 / self.successful_requests as f64;
        }
    }

    /// Success rate (0.0 - 1.0)
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.successful_requests as f64 / self.total_requests as f64
    }

    /// Cache hit rate (0.0 - 1.0)
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            return 0.0;
        }
        self.cache_hits as f64 / total as f64
    }

    /// Latency percentiles
    pub fn latency_p50(&self) -> u64 {
        self.latency_hist.value_at_percentile(50.0)
    }

    pub fn latency_p95(&self) -> u64 {
        self.latency_hist.value_at_percentile(95.0)
    }

    pub fn latency_p99(&self) -> u64 {
        self.latency_hist.value_at_percentile(99.0)
    }

    /// Hops percentiles
    pub fn hops_p50(&self) -> u64 {
        self.hops_hist.value_at_percentile(50.0)
    }

    pub fn hops_p95(&self) -> u64 {
        self.hops_hist.value_at_percentile(95.0)
    }

    /// Print summary report
    pub fn report(&self) -> String {
        format!(
            r#"=== Simulation Results ===
Requests: {} total, {} success, {} failed
Success rate: {:.1}%
Corrupted responses: {}

Latency (ms):
  p50: {}
  p95: {}
  p99: {}

Hops to find data:
  p50: {}
  p95: {}

Network overhead:
  Total messages: {}
  Messages per success: {:.1}

Cache:
  Hit rate: {:.1}%
"#,
            self.total_requests,
            self.successful_requests,
            self.failed_requests,
            self.success_rate() * 100.0,
            self.corrupted_responses,
            self.latency_p50(),
            self.latency_p95(),
            self.latency_p99(),
            self.hops_p50(),
            self.hops_p95(),
            self.total_messages,
            self.messages_per_success,
            self.cache_hit_rate() * 100.0,
        )
    }
}

impl Default for SimMetrics {
    fn default() -> Self {
        Self::new()
    }
}
