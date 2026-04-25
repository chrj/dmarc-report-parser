use dmarc_report_parser::{Aggregate, DkimResult, DmarcResult, Record, Report, SpfResult};

use super::{alignment_label, dkim_pass, dmarc_pass, format_timestamp, spf_pass};

/// Render a DMARC report as Markdown.
pub fn render(report: &Report) -> String {
    let meta = &report.report_metadata;
    let pol = &report.policy_published;
    let total_messages: u64 = report.records.iter().map(|r| r.row.count).sum();

    let mut md = String::new();

    // Title
    md.push_str(&format!("# DMARC Aggregate Report — {}\n\n", pol.domain));

    // Report source
    md.push_str("## Report Source\n\n");
    md.push_str("| Field | Value |\n|---|---|\n");
    md.push_str(&format!("| Organization | {} |\n", escape(&meta.org_name)));
    md.push_str(&format!("| Email | {} |\n", escape(&meta.email)));
    if let Some(ref info) = meta.extra_contact_info {
        md.push_str(&format!("| Contact Info | {} |\n", escape(info)));
    }
    md.push_str(&format!("| Report ID | {} |\n", escape(&meta.report_id)));
    md.push_str(&format!(
        "| Period | {} → {} |\n",
        format_timestamp(meta.date_range.begin),
        format_timestamp(meta.date_range.end)
    ));
    if !meta.errors.is_empty() {
        md.push_str(&format!("| Errors | {} |\n", meta.errors.join(", ")));
    }
    md.push('\n');

    // Published policy
    md.push_str("## Published Policy\n\n");
    md.push_str("| Field | Value |\n|---|---|\n");
    md.push_str(&format!("| Domain | {} |\n", escape(&pol.domain)));
    md.push_str(&format!("| Policy (p) | {} |\n", pol.p));
    md.push_str(&format!("| Sub-policy (sp) | {} |\n", pol.sp));
    md.push_str(&format!(
        "| DKIM Alignment | {} |\n",
        alignment_label(&pol.adkim)
    ));
    md.push_str(&format!(
        "| SPF Alignment | {} |\n",
        alignment_label(&pol.aspf)
    ));
    md.push_str(&format!("| Percentage | {}% |\n", pol.pct));
    if let Some(ref fo) = pol.fo {
        md.push_str(&format!("| Failure Options | {} |\n", fo));
    }
    md.push('\n');

    // Summary
    md.push_str("## Summary\n\n");
    md.push_str(&format!("- **Records:** {}\n", report.records.len()));
    md.push_str(&format!("- **Total Messages:** {total_messages}\n"));
    let pass_count: u64 = report
        .records
        .iter()
        .filter(|r| {
            dmarc_pass(r.row.policy_evaluated.dkim) && dmarc_pass(r.row.policy_evaluated.spf)
        })
        .map(|r| r.row.count)
        .sum();
    md.push_str(&format!("- **Fully Passing (DKIM + SPF):** {pass_count}\n"));
    md.push('\n');

    // Records table
    md.push_str("## Records\n\n");
    md.push_str("| Source IP | Count | Disposition | DKIM | SPF | Header From | Envelope From | Auth Details |\n");
    md.push_str("|---|---|---|---|---|---|---|---|\n");

    for record in &report.records {
        md.push_str(&format_record_row(record, None));
    }

    md.push('\n');
    md
}

/// Render an aggregate of multiple DMARC reports as Markdown.
pub fn render_aggregate(agg: &Aggregate) -> String {
    let mut md = String::new();

    md.push_str("# DMARC Aggregate Report\n\n");

    // Overview
    md.push_str("## Overview\n\n");
    md.push_str(&format!("- **Reports:** {}\n", agg.reports.len()));
    if let Some((begin, end)) = agg.date_span() {
        md.push_str(&format!(
            "- **Period:** {} → {}\n",
            format_timestamp(begin),
            format_timestamp(end)
        ));
    }
    md.push_str(&format!(
        "- **Total Records:** {}\n",
        agg.records().count()
    ));
    md.push_str(&format!(
        "- **Total Messages:** {}\n",
        agg.total_messages()
    ));
    let pass_count: u64 = agg
        .records()
        .filter(|(_, r)| {
            dmarc_pass(r.row.policy_evaluated.dkim) && dmarc_pass(r.row.policy_evaluated.spf)
        })
        .map(|(_, r)| r.row.count)
        .sum();
    md.push_str(&format!("- **Fully Passing (DKIM + SPF):** {pass_count}\n\n"));

    // Contributing reports
    md.push_str("## Reports\n\n");
    md.push_str("| Organization | Report ID | Domain | Period | Records | Messages |\n");
    md.push_str("|---|---|---|---|---|---|\n");
    for r in &agg.reports {
        let m = &r.report_metadata;
        let messages: u64 = r.records.iter().map(|rec| rec.row.count).sum();
        md.push_str(&format!(
            "| {} | {} | {} | {} → {} | {} | {} |\n",
            escape(&m.org_name),
            escape(&m.report_id),
            escape(&r.policy_published.domain),
            format_timestamp(m.date_range.begin),
            format_timestamp(m.date_range.end),
            r.records.len(),
            messages,
        ));
    }
    md.push('\n');

    // Combined records
    md.push_str("## Records\n\n");
    md.push_str("| Report | Source IP | Count | Disposition | DKIM | SPF | Header From | Envelope From | Auth Details |\n");
    md.push_str("|---|---|---|---|---|---|---|---|---|\n");
    for (report, record) in agg.records() {
        md.push_str(&format_record_row(
            record,
            Some(&report.report_metadata.report_id),
        ));
    }
    md.push('\n');

    md
}

fn format_record_row(record: &Record, report_id: Option<&str>) -> String {
    let row = &record.row;
    let ident = &record.identifiers;
    let auth = &record.auth_results;

    let mut auth_parts: Vec<String> = Vec::new();
    for dkim in &auth.dkim {
        let mut s = format!(
            "DKIM: {} {}",
            result_emoji_dkim(dkim.result),
            escape(&dkim.domain)
        );
        if let Some(ref sel) = dkim.selector {
            s.push_str(&format!(" (sel={})", escape(sel)));
        }
        auth_parts.push(s);
    }
    for spf in &auth.spf {
        let mut s = format!(
            "SPF: {} {}",
            result_emoji_spf(spf.result),
            escape(&spf.domain)
        );
        if let Some(ref scope) = spf.scope {
            s.push_str(&format!(" ({})", scope));
        }
        auth_parts.push(s);
    }

    let prefix = match report_id {
        Some(id) => format!("| {} |", escape(id)),
        None => String::from("|"),
    };

    format!(
        "{prefix} {} | {} | {} | {} | {} | {} | {} | {} |\n",
        escape(&row.source_ip),
        row.count,
        row.policy_evaluated.disposition,
        result_emoji_dmarc(row.policy_evaluated.dkim),
        result_emoji_dmarc(row.policy_evaluated.spf),
        escape(&ident.header_from),
        ident
            .envelope_from
            .as_deref()
            .map(escape)
            .unwrap_or_default(),
        auth_parts.join("; "),
    )
}

fn result_emoji_dmarc(result: DmarcResult) -> String {
    if dmarc_pass(result) {
        format!("✅ {result}")
    } else {
        format!("❌ {result}")
    }
}

fn result_emoji_dkim(result: DkimResult) -> String {
    if dkim_pass(result) {
        format!("✅ {result}")
    } else {
        format!("❌ {result}")
    }
}

fn result_emoji_spf(result: SpfResult) -> String {
    if spf_pass(result) {
        format!("✅ {result}")
    } else {
        format!("❌ {result}")
    }
}

/// Escape pipe characters for Markdown tables.
fn escape(s: &str) -> String {
    s.replace('|', "\\|")
}
