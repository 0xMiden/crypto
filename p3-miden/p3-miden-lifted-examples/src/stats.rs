//! A `tracing` `Layer` that collects wall-clock span durations across multiple
//! iterations and prints summary statistics (min / median / mean / max).
//!
//! Thread-safe: timing data is attached per-span via `Extensions`, so the
//! layer works correctly with rayon and other work-stealing runtimes.

use std::{
    collections::BTreeMap,
    format, println,
    string::String,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
    vec::Vec,
};

use tracing::{Subscriber, span};
use tracing_subscriber::{
    Registry,
    layer::{Context, Layer, SubscriberExt},
    registry::LookupSpan,
    util::SubscriberInitExt,
};

/// Newtype stored in span extensions to record creation time.
struct SpanStarted(Instant);

/// Cloneable handle to the accumulated span statistics.
///
/// Obtain via [`StatsLayer::handle`] before passing the layer to the subscriber.
#[derive(Clone)]
pub struct StatsHandle {
    inner: Arc<Mutex<BTreeMap<&'static str, Vec<Duration>>>>,
    enabled: Arc<AtomicBool>,
}

impl StatsHandle {
    /// Discard all accumulated durations (e.g. after a warm-up iteration).
    pub fn clear(&self) {
        self.inner.lock().expect("stats lock poisoned").clear();
    }

    /// Enable or disable collection. When disabled, `on_close` still fires
    /// but durations are not recorded.
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }

    /// Print a formatted summary table to stdout.
    pub fn print_summary(&self) {
        let map = self.inner.lock().expect("stats lock poisoned");
        if map.is_empty() {
            println!("(no span durations recorded)");
            return;
        }

        println!();
        println!(
            "{:<45} {:>6} {:>12} {:>12} {:>12} {:>12}",
            "span", "count", "min", "median", "mean", "max"
        );
        println!("{}", "-".repeat(105));

        for (name, durations) in map.iter() {
            let mut sorted = durations.clone();
            sorted.sort();
            let n = sorted.len();
            if n == 0 {
                continue;
            }

            let min = sorted[0];
            let max = sorted[n - 1];
            let median = if n % 2 == 1 {
                sorted[n / 2]
            } else {
                (sorted[n / 2 - 1] + sorted[n / 2]) / 2
            };
            let sum: Duration = sorted.iter().sum();
            let mean = sum / n as u32;

            println!(
                "{:<45} {:>6} {:>12} {:>12} {:>12} {:>12}",
                name,
                n,
                format_duration(min),
                format_duration(median),
                format_duration(mean),
                format_duration(max),
            );
        }
        println!();
    }
}

/// A tracing layer that records wall-clock durations of every span.
///
/// Durations are measured from span creation (`on_new_span`) to span close
/// (`on_close`), matching the `info_span!("name").in_scope(|| ...)` pattern
/// used throughout the codebase.
pub struct StatsLayer {
    inner: Arc<Mutex<BTreeMap<&'static str, Vec<Duration>>>>,
    enabled: Arc<AtomicBool>,
}

impl Default for StatsLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsLayer {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BTreeMap::new())),
            enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Get a cloneable handle to the stats. Call before passing `self` to the
    /// subscriber (which consumes the layer).
    pub fn handle(&self) -> StatsHandle {
        StatsHandle {
            inner: Arc::clone(&self.inner),
            enabled: Arc::clone(&self.enabled),
        }
    }
}

impl<S> Layer<S> for StatsLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, _attrs: &span::Attributes<'_>, id: &span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let mut extensions = span.extensions_mut();
            extensions.insert(SpanStarted(Instant::now()));
        }
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }

        if let Some(span) = ctx.span(&id) {
            let elapsed = {
                let extensions = span.extensions();
                match extensions.get::<SpanStarted>() {
                    Some(started) => started.0.elapsed(),
                    None => return,
                }
            };

            let name = span.name();
            let mut map = self.inner.lock().expect("stats lock poisoned");
            map.entry(name).or_default().push(elapsed);
        }
    }
}

/// Initialize tracing with [`StatsLayer`] + `ForestLayer`.
///
/// The forest layer respects `RUST_LOG`; the stats layer always records all spans.
/// Returns a [`StatsHandle`] for clearing warm-up data and printing summaries.
pub fn init_tracing() -> StatsHandle {
    let env_filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_forest::util::LevelFilter::DEBUG.into())
        .from_env_lossy();

    let stats = StatsLayer::new();
    let handle = stats.handle();

    Registry::default()
        .with(tracing_forest::ForestLayer::default().with_filter(env_filter))
        .with(stats)
        .init();

    handle
}

/// Parse `BENCH_ITERS` from the environment, defaulting to 5.
pub fn bench_iters() -> usize {
    std::env::var("BENCH_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5)
}

// ---------------------------------------------------------------------------
// Proof size measurement
// ---------------------------------------------------------------------------

/// Minimal serde `Serializer` that counts bytes without allocating.
///
/// Primitive widths: bool=1, u8/i8=1, u16/i16=2, u32/i32/f32=4, u64/i64/f64=8,
/// u128/i128=16, char=4. Sequences/structs/tuples are transparent (only their
/// elements contribute). This gives the raw payload size (sum of primitive
/// widths), ignoring framing overhead such as length prefixes. For fixed-width
/// field-element-heavy proofs this is a tight approximation of the minimum
/// serialized size.
struct SizeCounter {
    total: usize,
}

impl SizeCounter {
    fn new() -> Self {
        Self { total: 0 }
    }
}

/// Count the serialized size (in bytes) of a value.
pub fn serialized_size<T: serde::Serialize>(value: &T) -> usize {
    let mut counter = SizeCounter::new();
    value
        .serialize(&mut counter)
        .expect("SizeCounter is infallible");
    counter.total
}

/// Format a byte count as a human-readable string (B / KiB / MiB).
pub fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

// --- Serializer impl --------------------------------------------------------

/// Error type for `SizeCounter` (never actually produced).
#[derive(Debug)]
struct SizeError;

impl std::fmt::Display for SizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SizeCounter error")
    }
}

impl std::error::Error for SizeError {}

impl serde::ser::Error for SizeError {
    fn custom<T: std::fmt::Display>(_msg: T) -> Self {
        SizeError
    }
}

macro_rules! serialize_primitive {
    ($method:ident, $ty:ty, $size:expr) => {
        fn $method(self, _v: $ty) -> Result<Self::Ok, Self::Error> {
            self.total += $size;
            Ok(())
        }
    };
}

impl<'a> serde::Serializer for &'a mut SizeCounter {
    type Ok = ();
    type Error = SizeError;
    type SerializeSeq = &'a mut SizeCounter;
    type SerializeTuple = &'a mut SizeCounter;
    type SerializeTupleStruct = &'a mut SizeCounter;
    type SerializeTupleVariant = &'a mut SizeCounter;
    type SerializeMap = &'a mut SizeCounter;
    type SerializeStruct = &'a mut SizeCounter;
    type SerializeStructVariant = &'a mut SizeCounter;

    serialize_primitive!(serialize_bool, bool, 1);
    serialize_primitive!(serialize_i8, i8, 1);
    serialize_primitive!(serialize_i16, i16, 2);
    serialize_primitive!(serialize_i32, i32, 4);
    serialize_primitive!(serialize_i64, i64, 8);
    serialize_primitive!(serialize_i128, i128, 16);
    serialize_primitive!(serialize_u8, u8, 1);
    serialize_primitive!(serialize_u16, u16, 2);
    serialize_primitive!(serialize_u32, u32, 4);
    serialize_primitive!(serialize_u64, u64, 8);
    serialize_primitive!(serialize_u128, u128, 16);
    serialize_primitive!(serialize_f32, f32, 4);
    serialize_primitive!(serialize_f64, f64, 8);
    serialize_primitive!(serialize_char, char, 4);

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.total += v.len();
        Ok(())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.total += v.len();
        Ok(())
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_some<T: serde::Serialize + ?Sized>(
        self,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _idx: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_newtype_struct<T: serde::Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: serde::Serialize + ?Sized>(
        self,
        _name: &'static str,
        _idx: u32,
        _variant: &'static str,
        value: &T,
    ) -> Result<Self::Ok, Self::Error> {
        value.serialize(self)
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(self)
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(self)
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Ok(self)
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _idx: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        Ok(self)
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(self)
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(self)
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _idx: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(self)
    }
}

macro_rules! impl_compound {
    ($trait:ident, $method:ident) => {
        impl serde::ser::$trait for &mut SizeCounter {
            type Ok = ();
            type Error = SizeError;

            fn $method<T: serde::Serialize + ?Sized>(
                &mut self,
                value: &T,
            ) -> Result<(), Self::Error> {
                value.serialize(&mut **self)
            }

            fn end(self) -> Result<Self::Ok, Self::Error> {
                Ok(())
            }
        }
    };
}

impl_compound!(SerializeSeq, serialize_element);
impl_compound!(SerializeTuple, serialize_element);
impl_compound!(SerializeTupleStruct, serialize_field);
impl_compound!(SerializeTupleVariant, serialize_field);

impl serde::ser::SerializeMap for &mut SizeCounter {
    type Ok = ();
    type Error = SizeError;

    fn serialize_key<T: serde::Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Self::Error> {
        key.serialize(&mut **self)
    }

    fn serialize_value<T: serde::Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), Self::Error> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl serde::ser::SerializeStruct for &mut SizeCounter {
    type Ok = ();
    type Error = SizeError;

    fn serialize_field<T: serde::Serialize + ?Sized>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl serde::ser::SerializeStructVariant for &mut SizeCounter {
    type Ok = ();
    type Error = SizeError;

    fn serialize_field<T: serde::Serialize + ?Sized>(
        &mut self,
        _key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Duration formatting
// ---------------------------------------------------------------------------

fn format_duration(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos < 1_000 {
        format!("{nanos} ns")
    } else if nanos < 1_000_000 {
        format!("{:.1} us", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:.2} ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:.3} s", d.as_secs_f64())
    }
}
