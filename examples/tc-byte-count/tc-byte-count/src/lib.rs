use anyhow::{bail, Result};
use inc_stats::Percentiles;
use std::time::Instant;

/// Structure used to hold all aggregated values.
pub struct FlowStat {
    time: Instant,
    port: u16,
    rx: Percentiles<f64>,
    rx_total: u128,
    rx_counters: Vec<u64>,
    tx: Percentiles<f64>,
    tx_total: u128,
    tx_counters: Vec<u64>,
}

impl FlowStat {
    pub fn new(port: u16, num_cpus: usize) -> Self {
        Self {
            time: Instant::now(),
            port,
            rx: Percentiles::new(),
            rx_total: 0,
            rx_counters: vec![0; num_cpus],
            tx: Percentiles::new(),
            tx_total: 0,
            tx_counters: vec![0; num_cpus],
        }
    }

    pub fn add_rx(&mut self, rx: u64) {
        self.rx_total += rx as u128;
        self.rx.add(&(rx as f64));
    }

    pub fn add_tx(&mut self, tx: u64) {
        self.tx_total += tx as u128;
        self.tx.add(&(tx as f64));
    }

    pub fn aggregate_rx(&mut self, index: usize, rx_new: u64) -> u64 {
        let rx_prev = self.rx_counters[index];
        let delta = if rx_prev > rx_new {
            rx_new
        } else {
            rx_new - rx_prev
        };
        self.rx_counters[index] = rx_new;
        delta
    }

    pub fn aggregate_tx(&mut self, index: usize, tx_new: u64) -> u64 {
        let tx_prev = self.tx_counters[index];
        let delta = if tx_prev > tx_new {
            tx_new
        } else {
            tx_new - tx_prev
        };
        self.tx_counters[index] = tx_new;
        delta
    }

    pub fn has_traffic(&self) -> bool {
        self.rx_total > 0 || self.tx_total > 0
    }

    pub fn reset(&mut self) {
        self.time = Instant::now();
        self.rx_total = 0;
        self.rx = Percentiles::new();
        self.tx_total = 0;
        self.tx = Percentiles::new();
    }

    /// Produce a summary of the FlowStat since the last summary. The Percentiles are managed here.
    pub fn summary(&mut self, reset: bool) -> Result<FlowStatSummary> {
        let (rx_p100, rx_p90, rx_p75, rx_p50) = match self.rx.percentiles(&[1.0, 0.90, 0.75, 0.50])
        {
            Ok(Some(result)) => (result[0], result[1], result[2], result[3]),
            _ => bail!("Error generating percentiles"),
        };
        //  .ok_or_else(|| anyhow!("Unexpected error with percentiles"))??;
        let (tx_p100, tx_p90, tx_p75, tx_p50) = match self.tx.percentiles(&[1.0, 0.90, 0.75, 0.50])
        {
            Ok(Some(result)) => (result[0], result[1], result[2], result[3]),
            _ => bail!("Error generating percentiles"),
        };
        let sample = FlowStatSummary {
            start_time: self.time,
            port: self.port,
            rx_p50,
            rx_p75,
            rx_p90,
            rx_p100,
            rx_total: self.rx_total,
            tx_p50,
            tx_p75,
            tx_p90,
            tx_p100,
            tx_total: self.tx_total,
        };

        if reset {
            self.reset();
        }

        Ok(sample)
    }
}

pub struct FlowStatSummary {
    pub start_time: Instant,
    pub port: u16,
    pub rx_p50: f64,
    pub rx_p75: f64,
    pub rx_p90: f64,
    pub rx_p100: f64,
    pub rx_total: u128,
    pub tx_p50: f64,
    pub tx_p75: f64,
    pub tx_p90: f64,
    pub tx_p100: f64,
    pub tx_total: u128,
}
