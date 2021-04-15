use crate::Opts;
use slog::{Drain, Level, LevelFilter, Logger};
use std::fs::File;
use std::path::PathBuf;

/// The logging mode to use.
enum LoggingMode {
    /// The default mode for logging; output without any decoration, to STDERR.
    Stderr,

    /// Tee logging to a file (in addition to STDERR). This mimics the verbose flag.
    /// So it would be similar to `dfx ... |& tee /some/file.txt
    Tee(PathBuf),

    /// Output Debug logs and up to a file, regardless of verbosity, keep the STDERR output
    /// the same (with verbosity).
    File(PathBuf),
}

fn create_drain(mode: LoggingMode) -> Logger {
    match mode {
        LoggingMode::File(out) => {
            let file = File::create(out).expect("Couldn't open log file");
            let decorator = slog_term::PlainDecorator::new(file);
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            Logger::root(slog_async::Async::new(drain).build().fuse(), slog::o!())
        }
        // A Tee mode is basically 2 drains duplicated.
        LoggingMode::Tee(out) => Logger::root(
            slog::Duplicate::new(
                create_drain(LoggingMode::Stderr),
                create_drain(LoggingMode::File(out)),
            )
            .fuse(),
            slog::o!(),
        ),
        LoggingMode::Stderr => {
            let decorator = slog_term::PlainDecorator::new(std::io::stderr());
            let drain = slog_term::CompactFormat::new(decorator).build().fuse();
            Logger::root(slog_async::Async::new(drain).build().fuse(), slog::o!())
        }
    }
}

pub(crate) fn setup_logging(opts: &Opts) -> Logger {
    // Create a logger with our argument matches.
    let verbose_level = opts.verbose as i64 - opts.quiet as i64;
    let logfile = opts.logfile.clone().unwrap_or_else(|| "log.txt".into());

    let mode = match opts.logmode.as_str() {
        "tee" => LoggingMode::Tee(logfile),
        "file" => LoggingMode::File(logfile),
        "stderr" => LoggingMode::Stderr,
        _ => unreachable!("unhandled logmode"),
    };

    let log_level = match verbose_level {
        -3 => Level::Critical,
        -2 => Level::Error,
        -1 => Level::Warning,
        0 => Level::Info,
        1 => Level::Debug,
        2 => Level::Trace,
        x => {
            if x > 0 {
                Level::Trace
            } else {
                // Silent.
                return Logger::root(slog::Discard, slog::o!());
            }
        }
    };

    let drain = LevelFilter::new(create_drain(mode), log_level).fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let root = Logger::root(drain, slog::o!("version" => clap::crate_version!()));
    slog::info!(root, "Log Level: {}", log_level);
    root
}
