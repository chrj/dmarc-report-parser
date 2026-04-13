# dmarc-report-parser

[![Crates.io](https://img.shields.io/crates/v/dmarc-report-parser)](https://crates.io/crates/dmarc-report-parser)
[![docs.rs](https://img.shields.io/docsrs/dmarc-report-parser)](https://docs.rs/dmarc-report-parser)
[![License: MIT](https://img.shields.io/crates/l/dmarc-report-parser)](LICENSE)

An [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489)-compliant DMARC aggregate report parser written in Rust.
It can be used both as a **library** in your own Rust projects and as a **standalone CLI tool**
for viewing reports in the terminal, as HTML, or as Markdown.

## Features

- Parses DMARC aggregate feedback XML as defined in [RFC 7489 Appendix C](https://www.rfc-editor.org/rfc/rfc7489#appendix-C)
- Zero-copy deserialization into strongly-typed Rust structs
- `FromStr`, `TryFrom<&str>`, and `TryFrom<&[u8]>` trait implementations for ergonomic usage
- Optional CLI with colorized terminal output, HTML, and Markdown rendering
- CLI supports `.xml`, `.xml.gz`, `.gz`, and `.zip` input files

## Installation

### As a library

Add the crate to your project:

```sh
cargo add dmarc-report-parser
```

### As a CLI tool

Install with the `cli` feature enabled:

```sh
cargo install dmarc-report-parser --features cli
```

This installs the `dmarc-report` binary.

## Library usage

### Parsing from a string

```rust
use dmarc_report_parser::{parse, Report};

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

let report: Report = parse(xml).unwrap();
assert_eq!(report.report_metadata.org_name, "Example Corp");
assert_eq!(report.records.len(), 1);
```

### Parsing from bytes

```rust
let xml_bytes: &[u8] = b"<?xml version=\"1.0\"?>
<feedback>
  <report_metadata>
    <org_name>Test</org_name>
    <email>test@example.com</email>
    <report_id>1</report_id>
    <date_range><begin>0</begin><end>0</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain><p>none</p><sp>none</sp><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>127.0.0.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><envelope_from>example.com</envelope_from><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>";

let report = dmarc_report_parser::parse_bytes(xml_bytes).unwrap();
assert_eq!(report.report_metadata.org_name, "Test");
```

### Using `FromStr` / `TryFrom`

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
let report = Report::from_str(xml).unwrap();
let report: Report = xml.parse().unwrap();
let report = Report::try_from(xml).unwrap();
```

## CLI usage

The `dmarc-report` CLI reads a DMARC aggregate report file and renders it in the
chosen format.

```text
Usage: dmarc-report [OPTIONS] <FILE>

Arguments:
  <FILE>  Path to a DMARC report file (.xml, .xml.gz, .zip, or .gz)

Options:
  -f, --format <FORMAT>  Output format [default: terminal]
                         [possible values: terminal, html, markdown]
  -o, --output <FILE>    Write output to a file instead of stdout
  -h, --help             Print help
  -V, --version          Print version
```

### Examples

```sh
# Display a report in the terminal with colors
dmarc-report report.xml

# Render as HTML and save to a file
dmarc-report report.xml --format html --output report.html

# Render as Markdown from a gzip-compressed report
dmarc-report report.xml.gz --format markdown

# Parse a report inside a zip archive
dmarc-report report.zip
```

## Supported types

The library exposes the full RFC 7489 Appendix C schema as Rust types:

| Type | Description |
|------|-------------|
| `Report` | Top-level aggregate feedback report |
| `ReportMetadata` | Report generator metadata |
| `DateRange` | UTC time range (Unix timestamps) |
| `PolicyPublished` | Published DMARC policy for the domain |
| `Record` | A single message record |
| `Row` | Per-message data row |
| `PolicyEvaluated` | DMARC evaluation results |
| `PolicyOverrideReason` | Reason for policy override |
| `Identifiers` | Message identifiers |
| `AuthResults` | Authentication results |
| `DkimAuthResult` | DKIM signature evaluation result |
| `SpfAuthResult` | SPF check result |

And enums: `AlignmentMode`, `Disposition`, `DmarcResult`, `DkimResult`, `SpfResult`,
`SpfDomainScope`, `PolicyOverride`.

## License

MIT — see [LICENSE](LICENSE) for details.
