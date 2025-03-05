use anyhow::Result;
use aya::{
    include_bytes_aligned,
    maps::{MapData, PerCpuHashMap, PerCpuValues},
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{error, info, warn};
use lru::LruCache;
use std::{num::NonZeroUsize, time::Instant};
use tc_byte_count::FlowStat;
use tokio::time::{sleep, Duration};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    env_logger::init();
    info!("Starting...");

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tc-byte-count"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tc-byte-count"
    ))?;

    if let Err(e) = EbpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}. This can be ignored if you have no log lines in your eBPF program.", e);
    }

    info!("Preparing eBPF programs and attachements...");

    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&opt.iface);

    // Prepare, load, and attach the eBPF program with entry-point function "tc_egress"
    // into the Kernel at the Egress attach point in the Traffic Control module.
    let egress_prg: &mut SchedClassifier =
        bpf.program_mut("tc_egress").unwrap().try_into()?;
    egress_prg.load()?;
    egress_prg.attach(&opt.iface, TcAttachType::Egress)?;

    // Prepare, load, and attach the eBPF program with entry-point function "tc_ingress"
    // into the Kernel at the Ingress attach point in the Traffic Control module.
    let ingress_prg: &mut SchedClassifier =
        bpf.program_mut("tc_ingress").unwrap().try_into()?;
    ingress_prg.load()?;
    ingress_prg.attach(&opt.iface, TcAttachType::Ingress)?;

    info!("Starting to gather telemetry...");

    // Get a handle to the INGRESS telemetry map from the tc_ingress eBPF program.
    // This map is a PreCpuHashMap so no locking is needed to coordinate aggregation.
    let ingress: PerCpuHashMap<&MapData, u16, u64> =
        PerCpuHashMap::try_from(bpf.map("INGRESS").unwrap())?;

    // Get a handle to the EGRESS telemetry map from the tc_egress eBPF program.
    // This map is a PreCpuHashMap so no locking is needed to coordinate aggregation.
    let egress: PerCpuHashMap<&MapData, u16, u64> =
        PerCpuHashMap::try_from(bpf.map("EGRESS").unwrap())?;

    // Prepare an LRU Map for this userspace process to use when preparing aggregations across
    // time windows, cpus, and ports.
    let mut flows: LruCache<u16, FlowStat> =
        LruCache::new(NonZeroUsize::new(1000).unwrap());

    let sample_interval_millis = 20;
    let summary_interval_millis = 1000;
    let mut last_summary = Instant::now();
    loop {
        // Simple loop that drives the main execution of our userspace aggregator.
        // Every sample_interval (e.g. 20 ms ) milliseconds, we aggregate all per-cpu
        // values for every port in the egress and ingress map. The bytes transfered since
        // the previous aggregation are then stored by port for both rx and tx. After
        // summary_interval (e.g. 1000 ms) samples are taken at the sample_interval_millis
        // we produce a summary for each port that was active since the previous summary that includes:
        // total_bytes transfered since the last summary, p50, p75, p90, and p100 bytes transferred in a sample.
        sleep(Duration::from_millis(sample_interval_millis)).await;

        //Aggregate the raw RX and TX data from the eBPF program via the PerCpuHashMap
        aggregate_map(Direction::EGRESS, &mut flows, &egress);
        aggregate_map(Direction::INGRESS, &mut flows, &ingress);

        // Print a summary of the last summary_interval_samples samples for each port that had traffic since the last summary.
        if last_summary.elapsed().as_millis() >= summary_interval_millis {
            summarize_map(&mut flows);
            last_summary = Instant::now();
        }
    }
}

/// For each Port present in the given PerCpuMap, aggregate its values for this sample interval
/// into a FlowStat in our LRU cache.
fn aggregate_map(
    direction: Direction,
    cache: &mut LruCache<u16, FlowStat>,
    map: &PerCpuHashMap<&MapData, u16, u64>,
) {
    for next_item in map.iter() {
        match next_item {
            Ok((key, value)) => {
                aggregate_port(&direction, cache, (key, value));
            }
            Err(e) => {
                info!("error: {:?}", e);
            }
        }
    }
}

/// For a given port record, aggregate its telemetry across the PerCPU map entries  and also
/// add record the aggregate for this sample into the FlowStat for later use in percentile
/// calculations
fn aggregate_port(
    direction: &Direction,
    cache: &mut LruCache<u16, FlowStat>,
    record: (u16, PerCpuValues<u64>),
) {
    let mut total = 0;
    let len = record.1.len();
    let port = record.0;

    //Setup the function that will produce the 'default' value when a new entry is needed in the cache
    let default = move || FlowStat::new(port, len);

    //Get the existing record from the cache for this port - or the default record we will use to seed the port.
    let existing_record = cache.get_or_insert_mut(record.0, default);

    //For each CPU in the PerCPU map, aggregate the values for this sample into the FlowStat
    for (i, new_value) in record.1.iter().enumerate() {
        //keep a running total so we know when to add the value to the population used by the percentile calculator
        total += match direction {
            Direction::INGRESS => existing_record.aggregate_rx(i, *new_value),
            Direction::EGRESS => existing_record.aggregate_tx(i, *new_value),
        };
    }

    //add the aggregated value to the percentile population
    match direction {
        Direction::INGRESS => existing_record.add_rx(total),
        Direction::EGRESS => existing_record.add_tx(total),
    };
}

/// For each port in the given LRU cache, produce a summary of the samples since the last summary.
fn summarize_map(flows: &mut LruCache<u16, FlowStat>) {
    for (key, value) in flows.iter_mut() {
        //Only consider ports that had any traffic in the interval
        if value.has_traffic() {
            //When producing the summary, ensure the FlowStat resets its internal state in preparation
            //for the next sample interval.
            match value.summary(true) {
                Ok(summary) => {
                    info!(
                        "Port: {} - rxt:{}, rx50:{}, rx75:{}, rx90:{}, rx100:{} - txt:{}, tx50:{}, tx75:{}, tx90:{}, tx100:{}",
                        summary.port,
                        summary.rx_total,
                        summary.rx_p50,
                        summary.rx_p75,
                        summary.rx_p90,
                        summary.rx_p100,
                        summary.tx_total,
                        summary.tx_p50,
                        summary.tx_p75,
                        summary.tx_p90,
                        summary.tx_p100,
                    );
                }
                Err(e) => {
                    error!("Unable to process summary for {} {:?}", key, e);
                }
            }
        } else {
            value.reset();
        }
    }
}

enum Direction {
    INGRESS,
    EGRESS,
}
