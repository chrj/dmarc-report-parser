# Library usage

`dmarc-report-parser` exposes a small, focused API for parsing DMARC aggregate
feedback reports from their XML representation as defined in
[RFC 7489 Appendix C](https://www.rfc-editor.org/rfc/rfc7489#appendix-C).

## Parsing a report

The primary entry point is [`parse`], which accepts an XML string and returns a
[`Report`]:

```rust
let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>Example Corp</org_name>
    <email>dmarc@example.com</email>
    <report_id>abc123</report_id>
    <date_range>
      <begin>1609459200</begin>
      <end>1609545600</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>none</p>
    <sp>none</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.1</source_ip>
      <count>5</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_from>example.com</envelope_from>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>example.com</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>"#;

let report = dmarc_report_parser::parse(xml).unwrap();
assert_eq!(report.report_metadata.org_name, "Example Corp");
```

If you have raw bytes instead of a string, use [`parse_bytes`]:

```rust
# let xml_bytes: &[u8] = b"<?xml version=\"1.0\"?>
# <feedback>
#   <report_metadata>
#     <org_name>Test</org_name><email>t@e.com</email><report_id>1</report_id>
#     <date_range><begin>0</begin><end>0</end></date_range>
#   </report_metadata>
#   <policy_published><domain>e.com</domain><p>none</p><sp>none</sp><pct>100</pct></policy_published>
#   <record>
#     <row><source_ip>127.0.0.1</source_ip><count>1</count>
#       <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
#     </row>
#     <identifiers><envelope_from>e.com</envelope_from><header_from>e.com</header_from></identifiers>
#     <auth_results><spf><domain>e.com</domain><result>pass</result></spf></auth_results>
#   </record>
# </feedback>";
let report = dmarc_report_parser::parse_bytes(xml_bytes).unwrap();
```

## Trait-based parsing

[`Report`] implements [`FromStr`](std::str::FromStr), [`TryFrom<&str>`], and
[`TryFrom<&[u8]>`] so you can use whichever style fits your code:

```rust
use std::str::FromStr;
use dmarc_report_parser::Report;

# let xml = r#"<?xml version="1.0"?>
# <feedback>
#   <report_metadata>
#     <org_name>Test</org_name><email>t@e.com</email><report_id>1</report_id>
#     <date_range><begin>0</begin><end>0</end></date_range>
#   </report_metadata>
#   <policy_published><domain>e.com</domain><p>none</p><sp>none</sp><pct>100</pct></policy_published>
#   <record>
#     <row><source_ip>127.0.0.1</source_ip><count>1</count>
#       <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
#     </row>
#     <identifiers><envelope_from>e.com</envelope_from><header_from>e.com</header_from></identifiers>
#     <auth_results><spf><domain>e.com</domain><result>pass</result></spf></auth_results>
#   </record>
# </feedback>"#;
// Using FromStr
let report = Report::from_str(xml).unwrap();

// Using str::parse
let report: Report = xml.parse().unwrap();

// Using TryFrom
let report = Report::try_from(xml).unwrap();
```

## Error handling

Both [`parse`] and [`parse_bytes`] return `Result<Report, Error>`. The [`Error`]
type has two variants:

- **`Error::Parse`** — the XML is malformed or does not match the DMARC report
  schema.
- **`Error::Utf8`** — the input bytes are not valid UTF-8 (only from
  `parse_bytes` / `TryFrom<&[u8]>`).

## Combining multiple reports

If you have several parsed reports and want to view them together — for
example to compute totals across a quarter's worth of feedback — wrap them in
an [`Aggregate`]. It does not fabricate merged metadata; instead it preserves
each underlying [`Report`] and lets you iterate every record paired with its
source report.

```rust
# let xml = r#"<?xml version="1.0"?>
# <feedback>
#   <report_metadata>
#     <org_name>Test</org_name><email>t@e.com</email><report_id>1</report_id>
#     <date_range><begin>0</begin><end>86400</end></date_range>
#   </report_metadata>
#   <policy_published><domain>e.com</domain><p>none</p><sp>none</sp><pct>100</pct></policy_published>
#   <record>
#     <row><source_ip>127.0.0.1</source_ip><count>4</count>
#       <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
#     </row>
#     <identifiers><envelope_from>e.com</envelope_from><header_from>e.com</header_from></identifiers>
#     <auth_results><spf><domain>e.com</domain><result>pass</result></spf></auth_results>
#   </record>
# </feedback>"#;
use dmarc_report_parser::{parse, Aggregate};

let reports = vec![parse(xml).unwrap(), parse(xml).unwrap()];
let agg = Aggregate::from_reports(reports);

assert_eq!(agg.reports.len(), 2);
assert_eq!(agg.total_messages(), 8);
assert_eq!(agg.date_span(), Some((0, 86_400)));

for (report, record) in agg.records() {
    println!(
        "{} sent {} message(s) (from report {})",
        record.row.source_ip,
        record.row.count,
        report.report_metadata.report_id,
    );
}
```

## Working with the report

Once parsed, you can access every field of the RFC 7489 schema through the
strongly-typed structs:

```rust
# let xml = r#"<?xml version="1.0"?>
# <feedback>
#   <report_metadata>
#     <org_name>Test</org_name><email>t@e.com</email><report_id>1</report_id>
#     <date_range><begin>0</begin><end>0</end></date_range>
#   </report_metadata>
#   <policy_published><domain>e.com</domain><p>none</p><sp>none</sp><pct>100</pct></policy_published>
#   <record>
#     <row><source_ip>127.0.0.1</source_ip><count>1</count>
#       <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
#     </row>
#     <identifiers><envelope_from>e.com</envelope_from><header_from>e.com</header_from></identifiers>
#     <auth_results><spf><domain>e.com</domain><result>pass</result></spf></auth_results>
#   </record>
# </feedback>"#;
use dmarc_report_parser::{parse, DmarcResult};

let report = parse(xml).unwrap();

// Iterate over records and check results
for record in &report.records {
    let ip = &record.row.source_ip;
    let count = record.row.count;
    let dkim = record.row.policy_evaluated.dkim;
    let spf = record.row.policy_evaluated.spf;

    if dkim == DmarcResult::Fail || spf == DmarcResult::Fail {
        println!("{ip} sent {count} message(s) that failed DMARC");
    }
}
```
