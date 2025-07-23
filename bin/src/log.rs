//! Logging implementation based on [`tracing`].

use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap},
    fmt,
    fmt::Debug,
    io, str,
};

use serde::{
    Serialize,
    ser::{SerializeMap, Serializer as _},
};
use serde_json::Serializer;
use time::{
    OffsetDateTime as DateTime, format_description::well_known::Rfc3339,
};
use tracing::{
    Event, Metadata, Subscriber, field::Field, subscriber::Interest,
};
use tracing_log::NormalizeEvent as _;
use tracing_record_hierarchical::HierarchicalRecord;
use tracing_serde::AsSerde as _;
use tracing_subscriber::{
    Layer as _,
    field::Visit,
    filter::{LevelFilter, filter_fn},
    fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields, format},
    layer,
    layer::{Filter, SubscriberExt as _},
    registry::LookupSpan,
    util::SubscriberInitExt as _,
};

use crate::conf;

/// Initializes [`tracing`] backend and all the tools relying on it:
/// - Global structured logger with the configured [`Level`].
///
/// [`Level`]: tracing::Level
pub(crate) fn init(config: conf::Log) {
    /// `Level`s outputted in `stderr`.
    const STDERR_LEVELS: &[tracing::Level] =
        &[tracing::Level::WARN, tracing::Level::ERROR];

    let filter = ModuleFilter::from(config);

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_thread_names(true)
                .with_writer(io::stderr)
                .event_format(JsonEventFormatter)
                .with_filter(filter_fn(|meta| {
                    // Filters only events, not spans.
                    meta.is_span() || STDERR_LEVELS.contains(meta.level())
                }))
                .with_filter(filter.clone()),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .with_thread_names(true)
                .event_format(JsonEventFormatter)
                .with_filter(filter_fn(|meta| {
                    // Filters only events, not spans.
                    meta.is_span() || !STDERR_LEVELS.contains(meta.level())
                }))
                .with_filter(filter),
        )
        .with(HierarchicalRecord::default())
        .init();
}

/// [`tracing`] [`Filter`] overriding [`Level`]s for specific modules.
///
/// Affects only [`Event`]s (not [`Span`]s), as intended to be used with console
/// output. This allows to preserve [`Span`] fields, even if they don't satisfy
/// [`Filter`]ing rules.
///
/// If [`Event`]'s module is a submodule of some specially-handled module, then
/// it will be affected too.
///
/// [`Level`]: tracing::Level
/// [`Span`]: tracing::Span
#[derive(Clone, Debug)]
struct ModuleFilter {
    /// Specifically handled modules.
    modules: HashMap<Box<str>, LevelFilter>,

    /// Default [`LevelFilter`].
    default_level: LevelFilter,
}

impl From<conf::Log> for ModuleFilter {
    fn from(conf: conf::Log) -> Self {
        Self {
            default_level: conf.level,
            modules: conf
                .r#mod
                .into_iter()
                .map(|(k, m)| (k, m.level))
                .collect(),
        }
    }
}

impl ModuleFilter {
    /// Indicates whether an [`Event`] should be enabled.
    fn is_enabled(&self, meta: &Metadata<'_>) -> bool {
        if meta.is_span() {
            return true;
        }

        let path = meta.module_path().unwrap_or_else(|| meta.target());
        let level = self
            .modules
            .iter()
            .find_map(|(mod_, lvl)| path.starts_with(&**mod_).then_some(*lvl))
            .unwrap_or(self.default_level);

        level >= *meta.level()
    }
}

impl<S> Filter<S> for ModuleFilter
where
    S: for<'a> LookupSpan<'a> + Subscriber,
{
    fn enabled(&self, meta: &Metadata<'_>, _: &layer::Context<'_, S>) -> bool {
        self.is_enabled(meta)
    }

    fn callsite_enabled(&self, meta: &'static Metadata<'static>) -> Interest {
        self.is_enabled(meta)
            .then(Interest::always)
            .unwrap_or_else(Interest::never)
    }
}

/// JSON formatter for [`tracing`] events.
struct JsonEventFormatter;

impl<S, N> FormatEvent<S, N> for JsonEventFormatter
where
    S: for<'a> LookupSpan<'a> + Subscriber,
    N: for<'a> FormatFields<'a> + 'static,
{
    #[expect(clippy::panic_in_result_fn, reason = "not happens")]
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: format::Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let normalized_meta = event.normalized_metadata();
        let meta = normalized_meta.as_ref().unwrap_or_else(|| event.metadata());

        let timestamp =
            DateTime::now_utc().format(&Rfc3339).unwrap_or_else(|e| {
                panic!("cannot format `DateTime` as RFC 3339: {e}")
            });

        let mut visit = || {
            let mut ser = Serializer::new(WriteAdapter::new(&mut writer));
            let mut ser = ser.serialize_map(None)?;

            let mut span_fields = BTreeMap::new();
            ctx.visit_spans(|span| {
                if let Some(fields) =
                    span.extensions().get::<FormattedFields<N>>()
                {
                    let json = serde_json::from_str(&fields.fields)?;
                    if let serde_json::Value::Object(obj) = json {
                        for (key, value) in obj {
                            _ = span_fields.entry(key).or_insert(value);
                        }
                    }
                }
                Ok(())
            })?;

            for (key, value) in &span_fields {
                ser.serialize_entry(key, value)?;
            }

            ser.serialize_entry("log", "app.log")?;
            ser.serialize_entry("time", &timestamp)?;
            ser.serialize_entry("lvl", &meta.level().as_serde())?;
            ser.serialize_entry("mod", &meta.module_path())?;
            _ = (*meta.level() != tracing::Level::INFO)
                .then(|| {
                    meta.file().map(|file| {
                        meta.line().map_or_else(
                            || Cow::from(file),
                            |line| format!("{file}:{line}").into(),
                        )
                    })
                })
                .flatten()
                .map(|f| ser.serialize_entry("src", f.as_ref()))
                .transpose()?;

            let mut visitor = JsonEventVisitor::new(ser);
            event.record(&mut visitor);
            visitor.finish()
        };

        #[expect(clippy::map_err_ignore, reason = "no way to wrap")]
        visit().map_err(|_| fmt::Error)?;
        writeln!(writer)
    }
}

/// [`Visit`] implementor for a [`JsonEventFormatter`].
///
/// [`JsonEventVisitor`] also normalizes events from [`log`] crate, so they
/// appear identical to [`tracing`] ones.
///
/// [`log`]: https://docs.rs/log
struct JsonEventVisitor<S: SerializeMap> {
    /// Inner [`Serializer`] of this [`JsonEventVisitor`].
    serializer: S,

    /// Inner state of this [`JsonEventVisitor`].
    state: Result<(), S::Error>,
}

impl<S: SerializeMap> JsonEventVisitor<S> {
    /// Creates a new [`JsonEventVisitor`] with the given `serializer`.
    #[must_use]
    #[inline]
    const fn new(serializer: S) -> Self {
        Self { serializer, state: Ok(()) }
    }

    /// Attempts to write the given `value` with the `field.name()` as its key.
    fn write_inner<V: Serialize>(&mut self, field: &Field, value: V) {
        if self.state.is_ok() {
            let name = field.name();
            // `log` crate writes all fields except "message" with the "log"
            // prefix, so we strip "log." whenever it's possible to normalize
            // them.
            let normalized_name = match name
                .strip_prefix("log.")
                .unwrap_or(name)
            {
                "message" => "msg",
                // `log` includes meta fields as part of the event, but they're
                // already populated at this moment, so we skip them.
                "mod" | "module_path" | "file" | "target" | "line" => return,
                name => name,
            };

            self.state =
                self.serializer.serialize_entry(normalized_name, &value);
        }
    }

    /// Completes serializing of the visited object, returning [`Ok`]`(())` if
    /// all the fields were serialized correctly, or [`Err`]`(S::Error)` if a
    /// field cannot be serialized.
    fn finish(self) -> Result<S::Ok, S::Error> {
        self.state?;
        self.serializer.end()
    }
}

impl<S: SerializeMap> Visit for JsonEventVisitor<S> {
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.write_inner(field, value);
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.write_inner(field, value);
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.write_inner(field, value);
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.write_inner(field, value);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.write_inner(field, value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.write_inner(field, format_args!("{value:?}"));
    }
}

/// Bridge between a [`fmt::Write`] and an [`io::Write`].
///
/// Required because a [`FormatEvent`] expects a [`fmt::Write`], while
/// [`serde_json::Serializer`] expects an [`io::Write`].
struct WriteAdapter<'a> {
    /// Adapted writer.
    fmt_write: &'a mut dyn fmt::Write,
}

impl<'a> WriteAdapter<'a> {
    /// Creates a new [`WriteAdapter`].
    fn new(fmt_write: &'a mut dyn fmt::Write) -> Self {
        Self { fmt_write }
    }
}

impl io::Write for WriteAdapter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let s = str::from_utf8(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        self.fmt_write.write_str(s).map_err(io::Error::other)?;

        Ok(s.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
