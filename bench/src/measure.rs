use std::time::{Duration, Instant};

/// Minimum wall time of one sample, so fast operations are averaged over many calls.
const MIN_SAMPLE_TIME: Duration = Duration::from_millis(200);

/// Unit a benchmark is reported in; every unit is derived from seconds per call.
#[derive(Clone, Copy)]
pub enum Unit {
    /// Throughput over a payload of the given size, in 10^6 bytes per second.
    MegabytesPerSecond(usize),
    OpsPerSecond,
    Milliseconds,
}

impl Unit {
    fn label(self) -> &'static str {
        match self {
            Unit::MegabytesPerSecond(_) => "MB/s",
            Unit::OpsPerSecond => "ops/s",
            Unit::Milliseconds => "ms",
        }
    }

    fn convert(self, seconds_per_call: f64) -> f64 {
        match self {
            Unit::MegabytesPerSecond(bytes) => bytes as f64 / seconds_per_call / 1e6,
            Unit::OpsPerSecond => 1.0 / seconds_per_call,
            Unit::Milliseconds => seconds_per_call * 1e3,
        }
    }
}

/// Times `op` over `samples` samples, each repeating it for at least `MIN_SAMPLE_TIME`
/// after one warm-up call. Returns seconds per call for each sample.
pub fn repeated<E>(samples: usize, mut op: impl FnMut() -> Result<(), E>) -> Result<Vec<f64>, E> {
    op()?;

    let mut timings = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        let mut calls = 0u32;
        while calls == 0 || start.elapsed() < MIN_SAMPLE_TIME {
            op()?;
            calls += 1;
        }
        timings.push(start.elapsed().as_secs_f64() / f64::from(calls));
    }

    Ok(timings)
}

/// Times `op` once per sample, without warm-up; for slow operations like prime generation.
pub fn single<E>(samples: usize, mut op: impl FnMut() -> Result<(), E>) -> Result<Vec<f64>, E> {
    let mut timings = Vec::with_capacity(samples);
    for _ in 0..samples {
        let start = Instant::now();
        op()?;
        timings.push(start.elapsed().as_secs_f64());
    }

    Ok(timings)
}

pub fn print_header() {
    println!("benchmark,unit,samples,median,min,max");
}

/// Prints one CSV row with the median, min and max of `timings` expressed in `unit`.
pub fn print_row(name: &str, unit: Unit, timings: &[f64]) {
    let mut values: Vec<f64> = timings.iter().map(|&t| unit.convert(t)).collect();
    values.sort_by(f64::total_cmp);

    let (Some(&min), Some(&max)) = (values.first(), values.last()) else {
        return;
    };
    let middle = values.len() / 2;
    let median = if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    };

    println!(
        "{name},{},{},{median:.3},{min:.3},{max:.3}",
        unit.label(),
        values.len()
    );
}
