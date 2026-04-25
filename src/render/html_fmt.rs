use dmarc_report_parser::{Aggregate, DkimResult, DmarcResult, Record, Report, SpfResult};

use super::{
    aggregate_summary, alignment_label, dkim_pass, dmarc_pass, format_timestamp, spf_pass,
};

const HTML_HEAD: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DMARC Report</title>
<style>
  :root {
    --pass: #16a34a;
    --fail: #dc2626;
    --bg: #f8fafc;
    --card: #ffffff;
    --border: #e2e8f0;
    --text: #1e293b;
    --muted: #64748b;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; line-height: 1.6; }
  h1 { font-size: 1.5rem; margin-bottom: 1.5rem; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1.25rem; }
  .card h2 { font-size: 1.1rem; margin-bottom: 0.75rem; color: var(--muted); }
  dl { display: grid; grid-template-columns: 10rem 1fr; gap: 0.25rem 1rem; }
  dt { font-weight: 600; color: var(--muted); }
  dd { margin: 0; }
  table { width: 100%; border-collapse: collapse; margin-top: 0.75rem; font-size: 0.9rem; }
  th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); }
  th { background: var(--bg); font-weight: 600; }
  .pass { color: var(--pass); font-weight: 700; }
  .fail { color: var(--fail); font-weight: 700; }
  .badge { display: inline-block; padding: 0.1em 0.5em; border-radius: 4px; font-size: 0.85em; font-weight: 600; }
  .badge-pass { background: #dcfce7; color: var(--pass); }
  .badge-fail { background: #fee2e2; color: var(--fail); }
  .summary { display: flex; gap: 2rem; flex-wrap: wrap; margin-top: 0.5rem; }
  .summary-item { text-align: center; }
  .summary-item .value { font-size: 1.5rem; font-weight: 700; }
  .summary-item .label { font-size: 0.8rem; color: var(--muted); }
  .auth-detail { font-size: 0.85rem; color: var(--muted); }
</style>
</head>
<body>
"#;

/// Render a DMARC report as a standalone HTML document with embedded styles.
pub fn render(report: &Report) -> String {
    let meta = &report.report_metadata;
    let pol = &report.policy_published;
    let total_messages: u64 = report.records.iter().map(|r| r.row.count).sum();

    let mut html = String::from(HTML_HEAD);

    // Header
    html.push_str(&format!(
        "<h1>DMARC Aggregate Report &mdash; {}</h1>\n",
        escape(&pol.domain)
    ));

    // Report source card
    html.push_str("<div class=\"card\">\n<h2>Report Source</h2>\n<dl>\n");
    dl_row(&mut html, "Organization", &meta.org_name);
    dl_row(&mut html, "Email", &meta.email);
    if let Some(ref info) = meta.extra_contact_info {
        dl_row(&mut html, "Contact Info", info);
    }
    dl_row(&mut html, "Report ID", &meta.report_id);
    dl_row(
        &mut html,
        "Period",
        &format!(
            "{} → {}",
            format_timestamp(meta.date_range.begin),
            format_timestamp(meta.date_range.end)
        ),
    );
    if !meta.errors.is_empty() {
        dl_row(&mut html, "Errors", &meta.errors.join(", "));
    }
    html.push_str("</dl>\n</div>\n");

    // Published policy card
    html.push_str("<div class=\"card\">\n<h2>Published Policy</h2>\n<dl>\n");
    dl_row(&mut html, "Domain", &pol.domain);
    dl_row(&mut html, "Policy (p)", &pol.p.to_string());
    dl_row(&mut html, "Sub-policy (sp)", &pol.sp.to_string());
    dl_row(&mut html, "DKIM Alignment", alignment_label(&pol.adkim));
    dl_row(&mut html, "SPF Alignment", alignment_label(&pol.aspf));
    dl_row(&mut html, "Percentage", &format!("{}%", pol.pct));
    if let Some(ref fo) = pol.fo {
        dl_row(&mut html, "Failure Options", fo);
    }
    html.push_str("</dl>\n</div>\n");

    // Summary
    html.push_str("<div class=\"card\">\n<h2>Summary</h2>\n<div class=\"summary\">\n");
    summary_item(&mut html, &report.records.len().to_string(), "Records");
    summary_item(&mut html, &total_messages.to_string(), "Messages");
    let pass_count: u64 = report
        .records
        .iter()
        .filter(|r| {
            dmarc_pass(r.row.policy_evaluated.dkim) && dmarc_pass(r.row.policy_evaluated.spf)
        })
        .map(|r| r.row.count)
        .sum();
    summary_item(&mut html, &pass_count.to_string(), "Fully Passing");
    html.push_str("</div>\n</div>\n");

    // Records table
    html.push_str("<div class=\"card\">\n<h2>Records</h2>\n");
    html.push_str("<table>\n<thead>\n<tr>");
    for hdr in &[
        "Source IP",
        "Count",
        "Disposition",
        "DKIM",
        "SPF",
        "Header From",
        "Envelope From",
        "Auth Details",
    ] {
        html.push_str(&format!("<th>{hdr}</th>"));
    }
    html.push_str("</tr>\n</thead>\n<tbody>\n");

    for record in &report.records {
        html.push_str(&record_row(record, None));
    }

    html.push_str("</tbody>\n</table>\n</div>\n");
    html.push_str("</body>\n</html>\n");
    html
}

/// Render an aggregate of multiple DMARC reports as a standalone HTML document.
pub fn render_aggregate(agg: &Aggregate) -> String {
    let mut html = String::from(HTML_HEAD);

    html.push_str("<h1>DMARC Aggregate Report</h1>\n");

    let (record_count, total_messages, pass_count) = aggregate_summary(agg);

    // Overview card
    html.push_str("<div class=\"card\">\n<h2>Overview</h2>\n<div class=\"summary\">\n");
    summary_item(&mut html, &agg.reports.len().to_string(), "Reports");
    summary_item(&mut html, &record_count.to_string(), "Records");
    summary_item(&mut html, &total_messages.to_string(), "Messages");
    summary_item(&mut html, &pass_count.to_string(), "Fully Passing");
    html.push_str("</div>\n");
    if let Some((begin, end)) = agg.date_span() {
        html.push_str(&format!(
            "<dl><dt>Period</dt><dd>{} → {}</dd></dl>\n",
            format_timestamp(begin),
            format_timestamp(end)
        ));
    }
    html.push_str("</div>\n");

    // Contributing reports
    html.push_str("<div class=\"card\">\n<h2>Reports</h2>\n");
    html.push_str("<table>\n<thead>\n<tr>");
    for hdr in &[
        "Organization",
        "Report ID",
        "Domain",
        "Period",
        "Records",
        "Messages",
    ] {
        html.push_str(&format!("<th>{hdr}</th>"));
    }
    html.push_str("</tr>\n</thead>\n<tbody>\n");
    for r in &agg.reports {
        let m = &r.report_metadata;
        let messages: u64 = r.records.iter().map(|rec| rec.row.count).sum();
        html.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{} → {}</td><td>{}</td><td>{}</td></tr>\n",
            escape(&m.org_name),
            escape(&m.report_id),
            escape(&r.policy_published.domain),
            format_timestamp(m.date_range.begin),
            format_timestamp(m.date_range.end),
            r.records.len(),
            messages,
        ));
    }
    html.push_str("</tbody>\n</table>\n</div>\n");

    // Combined records table
    html.push_str("<div class=\"card\">\n<h2>Records</h2>\n");
    html.push_str("<table>\n<thead>\n<tr>");
    for hdr in &[
        "Report",
        "Source IP",
        "Count",
        "Disposition",
        "DKIM",
        "SPF",
        "Header From",
        "Envelope From",
        "Auth Details",
    ] {
        html.push_str(&format!("<th>{hdr}</th>"));
    }
    html.push_str("</tr>\n</thead>\n<tbody>\n");
    for (report, record) in agg.records() {
        html.push_str(&record_row(record, Some(&report.report_metadata.report_id)));
    }
    html.push_str("</tbody>\n</table>\n</div>\n");

    html.push_str("</body>\n</html>\n");
    html
}

fn record_row(record: &Record, report_id: Option<&str>) -> String {
    let row = &record.row;
    let ident = &record.identifiers;
    let auth = &record.auth_results;

    let mut s = String::from("<tr>");
    if let Some(id) = report_id {
        s.push_str(&format!("<td>{}</td>", escape(id)));
    }
    s.push_str(&format!("<td>{}</td>", escape(&row.source_ip)));
    s.push_str(&format!("<td>{}</td>", row.count));
    s.push_str(&format!("<td>{}</td>", row.policy_evaluated.disposition));
    s.push_str(&format!(
        "<td>{}</td>",
        badge_dmarc(row.policy_evaluated.dkim)
    ));
    s.push_str(&format!(
        "<td>{}</td>",
        badge_dmarc(row.policy_evaluated.spf)
    ));
    s.push_str(&format!("<td>{}</td>", escape(&ident.header_from)));
    s.push_str(&format!(
        "<td>{}</td>",
        ident
            .envelope_from
            .as_deref()
            .map(escape)
            .unwrap_or_default()
    ));

    s.push_str("<td class=\"auth-detail\">");
    for dkim in &auth.dkim {
        s.push_str(&format!(
            "DKIM: {} <em>{}</em>",
            badge_dkim(dkim.result),
            escape(&dkim.domain)
        ));
        if let Some(ref sel) = dkim.selector {
            s.push_str(&format!(" (sel={})", escape(sel)));
        }
        s.push_str("<br>");
    }
    for spf in &auth.spf {
        s.push_str(&format!(
            "SPF: {} <em>{}</em>",
            badge_spf(spf.result),
            escape(&spf.domain)
        ));
        if let Some(ref scope) = spf.scope {
            s.push_str(&format!(" ({})", scope));
        }
        s.push_str("<br>");
    }
    s.push_str("</td></tr>\n");
    s
}

fn dl_row(html: &mut String, label: &str, value: &str) {
    html.push_str(&format!(
        "<dt>{}</dt><dd>{}</dd>\n",
        escape(label),
        escape(value)
    ));
}

fn summary_item(html: &mut String, value: &str, label: &str) {
    html.push_str(&format!(
        "<div class=\"summary-item\"><div class=\"value\">{value}</div><div class=\"label\">{label}</div></div>\n"
    ));
}

fn badge_dmarc(result: DmarcResult) -> String {
    let cls = if dmarc_pass(result) {
        "badge badge-pass"
    } else {
        "badge badge-fail"
    };
    format!("<span class=\"{cls}\">{result}</span>")
}

fn badge_dkim(result: DkimResult) -> String {
    let cls = if dkim_pass(result) {
        "badge badge-pass"
    } else {
        "badge badge-fail"
    };
    format!("<span class=\"{cls}\">{result}</span>")
}

fn badge_spf(result: SpfResult) -> String {
    let cls = if spf_pass(result) {
        "badge badge-pass"
    } else {
        "badge badge-fail"
    };
    format!("<span class=\"{cls}\">{result}</span>")
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
