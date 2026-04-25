mod html_fmt;
mod markdown_fmt;
mod terminal_fmt;

pub use html_fmt::render as html;
pub use html_fmt::render_aggregate as html_aggregate;
pub use markdown_fmt::render as markdown;
pub use markdown_fmt::render_aggregate as markdown_aggregate;
pub use terminal_fmt::render as terminal;
pub use terminal_fmt::render_aggregate as terminal_aggregate;

use chrono::DateTime;
use dmarc_report_parser::{AlignmentMode, DkimResult, DmarcResult, SpfResult};

/// Format a unix timestamp as a human-readable UTC datetime string.
pub(crate) fn format_timestamp(ts: i64) -> String {
    DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| ts.to_string())
}

/// Human label for alignment mode.
pub(crate) fn alignment_label(mode: &Option<AlignmentMode>) -> &'static str {
    match mode {
        Some(AlignmentMode::Relaxed) => "relaxed",
        Some(AlignmentMode::Strict) => "strict",
        None => "relaxed (default)",
    }
}

/// Whether a DmarcResult is passing.
pub(crate) fn dmarc_pass(r: DmarcResult) -> bool {
    r == DmarcResult::Pass
}

/// Whether a DkimResult is passing.
pub(crate) fn dkim_pass(r: DkimResult) -> bool {
    r == DkimResult::Pass
}

/// Whether an SpfResult is passing.
pub(crate) fn spf_pass(result: SpfResult) -> bool {
    result == SpfResult::Pass
}
