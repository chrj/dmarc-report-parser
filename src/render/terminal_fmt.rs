use colored::Colorize;
use dmarc_report_parser::{Aggregate, DkimResult, DmarcResult, Record, Report, SpfResult};

use super::{
    aggregate_summary, alignment_label, dkim_pass, dmarc_pass, format_timestamp, spf_pass,
};

/// Render a DMARC report as colorized terminal output.
pub fn render(report: &Report) -> String {
    let mut out = String::new();

    // ── Report metadata ──────────────────────────────────────────────────
    let meta = &report.report_metadata;
    out.push_str(&format!(
        "{}\n",
        "═══ DMARC Aggregate Report ═══".bold().cyan()
    ));
    out.push('\n');

    out.push_str(&format!("{}\n", "▶ Report Source".bold().underline()));
    out.push_str(&format!(
        "  Organization : {}\n",
        meta.org_name.bold().white()
    ));
    out.push_str(&format!("  Email        : {}\n", meta.email));
    if let Some(ref info) = meta.extra_contact_info {
        out.push_str(&format!("  Contact Info : {info}\n"));
    }
    out.push_str(&format!("  Report ID    : {}\n", meta.report_id));
    out.push_str(&format!(
        "  Period       : {} → {}\n",
        format_timestamp(meta.date_range.begin).green(),
        format_timestamp(meta.date_range.end).green()
    ));
    if !meta.errors.is_empty() {
        out.push_str(&format!(
            "  Errors       : {}\n",
            meta.errors.join(", ").red()
        ));
    }
    out.push('\n');

    // ── Published policy ─────────────────────────────────────────────────
    let pol = &report.policy_published;
    out.push_str(&format!("{}\n", "▶ Published Policy".bold().underline()));
    out.push_str(&format!("  Domain       : {}\n", pol.domain.bold().white()));
    out.push_str(&format!("  Policy (p)   : {}\n", pol.p));
    out.push_str(&format!("  Sub-policy   : {}\n", pol.sp));
    out.push_str(&format!(
        "  DKIM align   : {}\n",
        alignment_label(&pol.adkim)
    ));
    out.push_str(&format!(
        "  SPF align    : {}\n",
        alignment_label(&pol.aspf)
    ));
    out.push_str(&format!("  Percentage   : {}%\n", pol.pct));
    if let Some(ref fo) = pol.fo {
        out.push_str(&format!("  Failure opts : {fo}\n"));
    }
    out.push('\n');

    // ── Records ──────────────────────────────────────────────────────────
    let total_messages: u64 = report.records.iter().map(|r| r.row.count).sum();
    out.push_str(&format!(
        "{} ({} record(s), {} message(s))\n",
        "▶ Records".bold().underline(),
        report.records.len(),
        total_messages
    ));
    out.push('\n');

    for (i, record) in report.records.iter().enumerate() {
        out.push_str(&format_record_block(
            record,
            &format!("── Record {} ──", i + 1),
        ));
    }

    out
}

/// Render an aggregate of multiple DMARC reports as colorized terminal output.
pub fn render_aggregate(agg: &Aggregate) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "{}\n\n",
        "═══ DMARC Aggregate Report ═══".bold().cyan()
    ));

    // ── Overview ─────────────────────────────────────────────────────────
    out.push_str(&format!("{}\n", "▶ Overview".bold().underline()));
    out.push_str(&format!("  Reports        : {}\n", agg.reports.len()));
    if let Some((begin, end)) = agg.date_span() {
        out.push_str(&format!(
            "  Period         : {} → {}\n",
            format_timestamp(begin).green(),
            format_timestamp(end).green()
        ));
    }
    let (record_count, total_messages, pass_count) = aggregate_summary(agg);
    out.push_str(&format!("  Total Records  : {record_count}\n"));
    out.push_str(&format!("  Total Messages : {total_messages}\n"));
    out.push_str(&format!("  Fully Passing  : {pass_count}\n\n"));

    // ── Contributing reports ─────────────────────────────────────────────
    out.push_str(&format!("{}\n", "▶ Reports".bold().underline()));
    for r in &agg.reports {
        let m = &r.report_metadata;
        let messages: u64 = r.records.iter().map(|rec| rec.row.count).sum();
        out.push_str(&format!(
            "  {} {} ({}) — {} → {} — {} record(s), {} message(s)\n",
            m.org_name.bold().white(),
            m.report_id,
            r.policy_published.domain,
            format_timestamp(m.date_range.begin).green(),
            format_timestamp(m.date_range.end).green(),
            r.records.len(),
            messages,
        ));
    }
    out.push('\n');

    // ── Combined records ─────────────────────────────────────────────────
    out.push_str(&format!(
        "{} ({} record(s), {} message(s))\n\n",
        "▶ Records".bold().underline(),
        record_count,
        total_messages,
    ));

    for (report, record) in agg.records() {
        out.push_str(&format_record_block(
            record,
            &format!("── [{}] ──", report.report_metadata.report_id),
        ));
    }

    out
}

fn format_record_block(record: &Record, header: &str) -> String {
    let row = &record.row;
    let ident = &record.identifiers;
    let auth = &record.auth_results;
    let mut out = String::new();

    out.push_str(&format!(
        "  {}  Source IP: {}  Count: {}\n",
        header.bold(),
        row.source_ip.yellow(),
        row.count
    ));

    out.push_str(&format!(
        "    Disposition : {}   DKIM: {}   SPF: {}\n",
        row.policy_evaluated.disposition,
        colorize_dmarc(row.policy_evaluated.dkim),
        colorize_dmarc(row.policy_evaluated.spf),
    ));

    for reason in &row.policy_evaluated.reasons {
        let comment = reason.comment.as_deref().unwrap_or("");
        out.push_str(&format!(
            "    Override    : {} {}\n",
            reason.reason_type,
            if comment.is_empty() {
                String::new()
            } else {
                format!("({comment})")
            }
        ));
    }

    out.push_str(&format!("    Header From : {}", ident.header_from));
    if let Some(ref env_from) = ident.envelope_from {
        out.push_str(&format!("   Envelope From: {env_from}"));
    }
    if let Some(ref env_to) = ident.envelope_to {
        out.push_str(&format!("   Envelope To: {env_to}"));
    }
    out.push('\n');

    for dkim in &auth.dkim {
        out.push_str(&format!(
            "    DKIM        : {} domain={}{}{}\n",
            colorize_dkim(dkim.result),
            dkim.domain,
            dkim.selector
                .as_deref()
                .map(|s| format!(" selector={s}"))
                .unwrap_or_default(),
            dkim.human_result
                .as_deref()
                .map(|h| format!(" ({h})"))
                .unwrap_or_default(),
        ));
    }

    for spf in &auth.spf {
        out.push_str(&format!(
            "    SPF         : {} domain={}{}\n",
            colorize_spf(spf.result),
            spf.domain,
            spf.scope
                .as_ref()
                .map(|s| format!(" scope={s}"))
                .unwrap_or_default(),
        ));
    }

    out.push('\n');
    out
}

fn colorize_dmarc(result: DmarcResult) -> String {
    let s = result.to_string();
    if dmarc_pass(result) {
        s.green().bold().to_string()
    } else {
        s.red().bold().to_string()
    }
}

fn colorize_dkim(result: DkimResult) -> String {
    let s = result.to_string();
    if dkim_pass(result) {
        s.green().bold().to_string()
    } else {
        s.red().bold().to_string()
    }
}

fn colorize_spf(result: SpfResult) -> String {
    let s = result.to_string();
    if spf_pass(result) {
        s.green().bold().to_string()
    } else {
        s.red().bold().to_string()
    }
}
