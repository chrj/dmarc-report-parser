//! DMARC aggregate report parser (RFC 7489).
//!
//! Parse DMARC aggregate feedback reports from their XML representation as
//! defined in [RFC 7489 Appendix C](https://www.rfc-editor.org/rfc/rfc7489#appendix-C).
//!
#![doc = include_str!("../docs/library-usage.md")]
//!
//! # CLI
//!
#![doc = include_str!("../docs/cli-usage.md")]

mod error;
pub use error::Error;

use serde::Deserialize;

fn deserialize_optional_alignment<'de, D>(deserializer: D) -> Result<Option<AlignmentMode>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> serde::de::Visitor<'de> for Visitor {
        type Value = Option<AlignmentMode>;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("alignment mode 'r', 's', or empty")
        }

        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            match v {
                "" => Ok(None),
                "r" => Ok(Some(AlignmentMode::Relaxed)),
                "s" => Ok(Some(AlignmentMode::Strict)),
                other => Err(E::unknown_variant(other, &["r", "s"])),
            }
        }

        fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            // quick-xml represents <adkim></adkim> as {"$text": ""} rather than a plain string
            let mut text = String::new();
            while let Some(key) = map.next_key::<String>()? {
                let val: String = map.next_value()?;
                if key == "$text" {
                    text = val;
                }
            }
            self.visit_str(&text)
        }
    }

    deserializer.deserialize_any(Visitor)
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a DMARC aggregate report from an XML string.
///
/// # Errors
///
/// Returns [`Error::Parse`] if the XML is invalid or does not conform to the
/// DMARC aggregate report schema (RFC 7489 Appendix C).
pub fn parse(xml: &str) -> Result<Report, Error> {
    quick_xml::de::from_str(xml).map_err(Error::from)
}

/// Parse a DMARC aggregate report from a byte slice.
///
/// # Errors
///
/// Returns [`Error::Utf8`] if the bytes are not valid UTF-8, or
/// [`Error::Parse`] if the XML is invalid or non-conformant.
pub fn parse_bytes(bytes: &[u8]) -> Result<Report, Error> {
    let xml = std::str::from_utf8(bytes)?;
    parse(xml)
}

// ──────────────────────────────────────────────────────────────────────────────
// RFC 7489 Appendix C — DMARC XML schema types
// ──────────────────────────────────────────────────────────────────────────────

/// Top-level DMARC aggregate feedback report (`<feedback>`).
///
/// Defined as the root element in RFC 7489 Appendix C.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename = "feedback")]
pub struct Report {
    /// Report format version (optional, xs:decimal).
    #[serde(default)]
    pub version: Option<String>,

    /// Metadata about the report generator.
    pub report_metadata: ReportMetadata,

    /// The DMARC policy published for the domain covered by this report.
    pub policy_published: PolicyPublished,

    /// One or more individual message records.
    #[serde(rename = "record")]
    pub records: Vec<Record>,
}

/// Report generator metadata (`ReportMetadataType`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ReportMetadata {
    /// The name of the organization generating the report.
    pub org_name: String,

    /// Contact email address for the report generator.
    pub email: String,

    /// Additional contact information (optional).
    #[serde(default)]
    pub extra_contact_info: Option<String>,

    /// Unique identifier for this report.
    pub report_id: String,

    /// The UTC time range covered by the messages in this report.
    pub date_range: DateRange,

    /// Any errors encountered during report generation.
    #[serde(rename = "error", default)]
    pub errors: Vec<String>,
}

/// UTC time range covered by a report, expressed as Unix timestamps.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DateRange {
    /// Start of the time range (seconds since Unix epoch).
    pub begin: i64,

    /// End of the time range (seconds since Unix epoch).
    pub end: i64,
}

/// The DMARC policy published for the organizational domain (`PolicyPublishedType`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PolicyPublished {
    /// The domain to which the DMARC policy applies.
    pub domain: String,

    /// DKIM alignment mode (`r` = relaxed, `s` = strict). Defaults to relaxed when absent.
    #[serde(default, deserialize_with = "deserialize_optional_alignment")]
    pub adkim: Option<AlignmentMode>,

    /// SPF alignment mode (`r` = relaxed, `s` = strict). Defaults to relaxed when absent.
    #[serde(default, deserialize_with = "deserialize_optional_alignment")]
    pub aspf: Option<AlignmentMode>,

    /// Domain-level policy action.
    pub p: Disposition,

    /// Subdomain policy action.
    pub sp: Disposition,

    /// Percentage of messages to which the policy is applied (0–100).
    pub pct: u32,

    /// Failure reporting options (colon-separated list of `0`, `1`, `d`, `s`).
    #[serde(default)]
    pub fo: Option<String>,
}

/// DKIM / SPF alignment mode (`AlignmentType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
pub enum AlignmentMode {
    /// Relaxed alignment (default). Organisational domain match is sufficient.
    #[serde(rename = "r")]
    Relaxed,

    /// Strict alignment. Exact domain match is required.
    #[serde(rename = "s")]
    Strict,
}

impl std::fmt::Display for AlignmentMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlignmentMode::Relaxed => f.write_str("r"),
            AlignmentMode::Strict => f.write_str("s"),
        }
    }
}

/// Policy action applied to a message (`DispositionType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Disposition {
    /// No action taken; the message is delivered normally.
    None,
    /// The message is treated as suspicious and may be quarantined.
    Quarantine,
    /// The message is rejected.
    Reject,
}

impl std::fmt::Display for Disposition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Disposition::None => f.write_str("none"),
            Disposition::Quarantine => f.write_str("quarantine"),
            Disposition::Reject => f.write_str("reject"),
        }
    }
}

/// A single message record within a feedback report (`RecordType`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Record {
    /// Per-message row data.
    pub row: Row,

    /// Identifiers extracted from the message.
    pub identifiers: Identifiers,

    /// Authentication results for the message.
    pub auth_results: AuthResults,
}

/// Per-message data row (`RowType`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Row {
    /// The IP address of the sending mail server.
    pub source_ip: String,

    /// The number of messages covered by this row.
    pub count: u64,

    /// The applied DMARC policy evaluation results.
    pub policy_evaluated: PolicyEvaluated,
}

/// Results of applying DMARC to the messages in this row (`PolicyEvaluatedType`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PolicyEvaluated {
    /// The final policy action applied.
    pub disposition: Disposition,

    /// Whether the message passed DKIM alignment.
    pub dkim: DmarcResult,

    /// Whether the message passed SPF alignment.
    pub spf: DmarcResult,

    /// Reasons that may have altered the evaluated disposition.
    #[serde(rename = "reason", default)]
    pub reasons: Vec<PolicyOverrideReason>,
}

/// The DMARC-aligned authentication result (`DMARCResultType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DmarcResult {
    /// Authentication passed.
    Pass,
    /// Authentication failed.
    Fail,
}

impl std::fmt::Display for DmarcResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DmarcResult::Pass => f.write_str("pass"),
            DmarcResult::Fail => f.write_str("fail"),
        }
    }
}

/// A reason why the applied policy may differ from the published policy
/// (`PolicyOverrideReasonType`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PolicyOverrideReason {
    /// The type of policy override.
    #[serde(rename = "type")]
    pub reason_type: PolicyOverride,

    /// An optional human-readable comment about the override.
    #[serde(default)]
    pub comment: Option<String>,
}

/// Reason type for a policy override (`PolicyOverrideType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyOverride {
    /// Message was forwarded and could not be authenticated.
    Forwarded,
    /// Message was sampled out of the policy percentage.
    SampledOut,
    /// Message was from a trusted forwarder.
    TrustedForwarder,
    /// Message was processed by a mailing list.
    MailingList,
    /// Local policy overrode the published DMARC policy.
    LocalPolicy,
    /// Some other reason.
    Other,
}

impl std::fmt::Display for PolicyOverride {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyOverride::Forwarded => f.write_str("forwarded"),
            PolicyOverride::SampledOut => f.write_str("sampled_out"),
            PolicyOverride::TrustedForwarder => f.write_str("trusted_forwarder"),
            PolicyOverride::MailingList => f.write_str("mailing_list"),
            PolicyOverride::LocalPolicy => f.write_str("local_policy"),
            PolicyOverride::Other => f.write_str("other"),
        }
    }
}

/// Message identifiers (`IdentifierType`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Identifiers {
    /// The RFC 5321 `RCPT TO` domain, if available.
    #[serde(default)]
    pub envelope_to: Option<String>,

    /// The RFC 5321 `MAIL FROM` domain, if available.
    #[serde(default)]
    pub envelope_from: Option<String>,

    /// The RFC 5322 `From:` header domain.
    pub header_from: String,
}

/// Authentication results for a message (`AuthResultType`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AuthResults {
    /// DKIM signature evaluation results (zero or more).
    #[serde(rename = "dkim", default)]
    pub dkim: Vec<DkimAuthResult>,

    /// SPF evaluation results (one or more per RFC 7489).
    #[serde(rename = "spf")]
    pub spf: Vec<SpfAuthResult>,
}

/// Result of evaluating a single DKIM signature (`DKIMAuthResultType`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DkimAuthResult {
    /// The `d=` domain from the DKIM signature.
    pub domain: String,

    /// The `s=` selector from the DKIM signature.
    #[serde(default)]
    pub selector: Option<String>,

    /// The DKIM verification result.
    pub result: DkimResult,

    /// A human-readable result string.
    #[serde(default)]
    pub human_result: Option<String>,
}

/// DKIM verification result (`DKIMResultType`), per RFC 5451.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DkimResult {
    /// No DKIM signature was found.
    None,
    /// The DKIM signature verified successfully.
    Pass,
    /// The DKIM signature failed verification.
    Fail,
    /// The DKIM signature was rejected for policy reasons.
    Policy,
    /// The DKIM verification result was neutral.
    Neutral,
    /// A transient error occurred during DKIM verification.
    Temperror,
    /// A permanent error occurred during DKIM verification.
    Permerror,
}

impl std::fmt::Display for DkimResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DkimResult::None => f.write_str("none"),
            DkimResult::Pass => f.write_str("pass"),
            DkimResult::Fail => f.write_str("fail"),
            DkimResult::Policy => f.write_str("policy"),
            DkimResult::Neutral => f.write_str("neutral"),
            DkimResult::Temperror => f.write_str("temperror"),
            DkimResult::Permerror => f.write_str("permerror"),
        }
    }
}

/// Result of an SPF check (`SPFAuthResultType`).
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SpfAuthResult {
    /// The domain used for SPF evaluation.
    pub domain: String,

    /// The identity that was checked (HELO or MAIL FROM).
    #[serde(default)]
    pub scope: Option<SpfDomainScope>,

    /// The SPF evaluation result.
    pub result: SpfResult,
}

/// SPF identity scope (`SPFDomainScope`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpfDomainScope {
    /// The SMTP `HELO`/`EHLO` identity.
    Helo,
    /// The SMTP `MAIL FROM` identity.
    Mfrom,
}

impl std::fmt::Display for SpfDomainScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpfDomainScope::Helo => f.write_str("helo"),
            SpfDomainScope::Mfrom => f.write_str("mfrom"),
        }
    }
}

/// SPF evaluation result (`SPFResultType`), per RFC 7208.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SpfResult {
    /// No SPF record was found.
    None,
    /// The SPF check returned a neutral result.
    Neutral,
    /// The SPF check passed.
    Pass,
    /// The SPF check failed.
    Fail,
    /// The SPF check returned a soft-fail result.
    Softfail,
    /// A transient error occurred during SPF evaluation.
    Temperror,
    /// A permanent error occurred during SPF evaluation.
    Permerror,
}

impl std::fmt::Display for SpfResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpfResult::None => f.write_str("none"),
            SpfResult::Neutral => f.write_str("neutral"),
            SpfResult::Pass => f.write_str("pass"),
            SpfResult::Fail => f.write_str("fail"),
            SpfResult::Softfail => f.write_str("softfail"),
            SpfResult::Temperror => f.write_str("temperror"),
            SpfResult::Permerror => f.write_str("permerror"),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Aggregate view across multiple reports
// ──────────────────────────────────────────────────────────────────────────────

/// A combined view across multiple DMARC aggregate reports.
///
/// Each underlying [`Report`] retains its own metadata and `policy_published`
/// — there is intentionally no synthetic merged report, since fields like
/// `org_name`, `report_id`, and `date_range` cannot be honestly combined.
/// Use [`Aggregate::records`] to iterate every record paired with the report
/// it came from.
#[derive(Debug, Clone, PartialEq)]
pub struct Aggregate {
    /// The reports that make up the aggregate, in the order they were added.
    pub reports: Vec<Report>,
}

impl Aggregate {
    /// Build an aggregate from a collection of reports.
    pub fn from_reports(reports: Vec<Report>) -> Self {
        Self { reports }
    }

    /// Iterator over every record across every report, paired with the
    /// [`Report`] it came from.
    pub fn records(&self) -> impl Iterator<Item = (&Report, &Record)> {
        self.reports
            .iter()
            .flat_map(|r| r.records.iter().map(move |rec| (r, rec)))
    }

    /// Sum of `row.count` across every record.
    pub fn total_messages(&self) -> u64 {
        self.records().map(|(_, rec)| rec.row.count).sum()
    }

    /// Earliest `begin` and latest `end` across all reports' date ranges.
    /// Returns `None` if the aggregate contains no reports.
    pub fn date_span(&self) -> Option<(i64, i64)> {
        let begin = self
            .reports
            .iter()
            .map(|r| r.report_metadata.date_range.begin)
            .min()?;
        let end = self
            .reports
            .iter()
            .map(|r| r.report_metadata.date_range.end)
            .max()?;
        Some((begin, end))
    }
}

impl From<Vec<Report>> for Aggregate {
    fn from(reports: Vec<Report>) -> Self {
        Self::from_reports(reports)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Trait implementations for idiomatic Rust usage
// ──────────────────────────────────────────────────────────────────────────────

impl std::str::FromStr for Report {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse(s)
    }
}

impl TryFrom<&str> for Report {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        parse(s)
    }
}

impl TryFrom<&[u8]> for Report {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        parse_bytes(bytes)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal valid report — only required fields present
    const MINIMAL_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata>
    <org_name>Acme</org_name>
    <email>postmaster@acme.example</email>
    <report_id>20130901.r.acme.example</report_id>
    <date_range>
      <begin>1377993600</begin>
      <end>1378080000</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>acme.example</domain>
    <p>none</p>
    <sp>none</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.1</source_ip>
      <count>2</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_from>acme.example</envelope_from>
      <header_from>acme.example</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>acme.example</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>"#;

    #[test]
    fn parse_minimal_report() {
        let report = parse(MINIMAL_XML).unwrap();

        // metadata
        assert_eq!(report.report_metadata.org_name, "Acme");
        assert_eq!(report.report_metadata.email, "postmaster@acme.example");
        assert_eq!(report.report_metadata.report_id, "20130901.r.acme.example");
        assert_eq!(report.report_metadata.date_range.begin, 1_377_993_600);
        assert_eq!(report.report_metadata.date_range.end, 1_378_080_000);
        assert!(report.report_metadata.extra_contact_info.is_none());
        assert!(report.report_metadata.errors.is_empty());

        // policy published
        assert_eq!(report.policy_published.domain, "acme.example");
        assert_eq!(report.policy_published.p, Disposition::None);
        assert_eq!(report.policy_published.sp, Disposition::None);
        assert_eq!(report.policy_published.pct, 100);
        assert!(report.policy_published.adkim.is_none());
        assert!(report.policy_published.aspf.is_none());

        // records
        assert_eq!(report.records.len(), 1);
        let record = &report.records[0];
        assert_eq!(record.row.source_ip, "192.0.2.1");
        assert_eq!(record.row.count, 2);
        assert_eq!(record.row.policy_evaluated.disposition, Disposition::None);
        assert_eq!(record.row.policy_evaluated.dkim, DmarcResult::Pass);
        assert_eq!(record.row.policy_evaluated.spf, DmarcResult::Pass);
        assert!(record.row.policy_evaluated.reasons.is_empty());

        // identifiers
        assert!(record.identifiers.envelope_to.is_none());
        assert_eq!(
            record.identifiers.envelope_from.as_deref(),
            Some("acme.example")
        );
        assert_eq!(record.identifiers.header_from, "acme.example");

        // auth results
        assert!(record.auth_results.dkim.is_empty());
        assert_eq!(record.auth_results.spf.len(), 1);
        assert_eq!(record.auth_results.spf[0].domain, "acme.example");
        assert_eq!(record.auth_results.spf[0].result, SpfResult::Pass);
    }

    #[test]
    fn parse_full_report_all_optional_fields() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <version>1.0</version>
  <report_metadata>
    <org_name>Mail Service Provider</org_name>
    <email>dmarc-reports@msp.example</email>
    <extra_contact_info>https://msp.example/dmarc-info</extra_contact_info>
    <report_id>report-001</report_id>
    <date_range>
      <begin>1609459200</begin>
      <end>1609545600</end>
    </date_range>
    <error>Lookup for example.com failed transiently</error>
    <error>DNS timeout for subdomain.example.com</error>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>s</adkim>
    <aspf>s</aspf>
    <p>reject</p>
    <sp>quarantine</sp>
    <pct>50</pct>
    <fo>1</fo>
  </policy_published>
  <record>
    <row>
      <source_ip>198.51.100.42</source_ip>
      <count>10</count>
      <policy_evaluated>
        <disposition>reject</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
        <reason>
          <type>forwarded</type>
          <comment>Known forwarder</comment>
        </reason>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_to>example.com</envelope_to>
      <envelope_from>sender.example</envelope_from>
      <header_from>example.com</header_from>
    </identifiers>
    <auth_results>
      <dkim>
        <domain>example.com</domain>
        <selector>selector1</selector>
        <result>fail</result>
        <human_result>signature did not verify</human_result>
      </dkim>
      <spf>
        <domain>sender.example</domain>
        <scope>mfrom</scope>
        <result>fail</result>
      </spf>
    </auth_results>
  </record>
</feedback>"#;

        let report = parse(xml).unwrap();

        // optional version
        assert_eq!(report.version, Some("1.0".to_string()));

        // metadata extras
        assert_eq!(
            report.report_metadata.extra_contact_info,
            Some("https://msp.example/dmarc-info".to_string())
        );
        assert_eq!(report.report_metadata.errors.len(), 2);
        assert_eq!(
            report.report_metadata.errors[0],
            "Lookup for example.com failed transiently"
        );

        // policy published optional fields
        assert_eq!(report.policy_published.adkim, Some(AlignmentMode::Strict));
        assert_eq!(report.policy_published.aspf, Some(AlignmentMode::Strict));
        assert_eq!(report.policy_published.p, Disposition::Reject);
        assert_eq!(report.policy_published.sp, Disposition::Quarantine);
        assert_eq!(report.policy_published.pct, 50);
        assert_eq!(report.policy_published.fo, Some("1".to_string()));

        let record = &report.records[0];

        // policy override reason
        assert_eq!(record.row.policy_evaluated.reasons.len(), 1);
        let reason = &record.row.policy_evaluated.reasons[0];
        assert_eq!(reason.reason_type, PolicyOverride::Forwarded);
        assert_eq!(reason.comment, Some("Known forwarder".to_string()));

        // identifiers with envelope_to
        assert_eq!(
            record.identifiers.envelope_to,
            Some("example.com".to_string())
        );
        assert_eq!(
            record.identifiers.envelope_from.as_deref(),
            Some("sender.example")
        );

        // DKIM auth result
        assert_eq!(record.auth_results.dkim.len(), 1);
        let dkim = &record.auth_results.dkim[0];
        assert_eq!(dkim.domain, "example.com");
        assert_eq!(dkim.selector, Some("selector1".to_string()));
        assert_eq!(dkim.result, DkimResult::Fail);
        assert_eq!(
            dkim.human_result,
            Some("signature did not verify".to_string())
        );

        // SPF auth result with scope
        assert_eq!(
            record.auth_results.spf[0].scope,
            Some(SpfDomainScope::Mfrom)
        );
        assert_eq!(record.auth_results.spf[0].result, SpfResult::Fail);
    }

    #[test]
    fn parse_multiple_records() {
        let xml = r#"<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>Reporter</org_name>
    <email>r@reporter.example</email>
    <report_id>multi-001</report_id>
    <date_range><begin>0</begin><end>86400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>sender.example</domain>
    <p>quarantine</p>
    <sp>quarantine</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.1</source_ip>
      <count>1</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_from>sender.example</envelope_from>
      <header_from>sender.example</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>sender.example</domain>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>203.0.113.7</source_ip>
      <count>3</count>
      <policy_evaluated>
        <disposition>quarantine</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <envelope_from>attacker.example</envelope_from>
      <header_from>sender.example</header_from>
    </identifiers>
    <auth_results>
      <spf>
        <domain>attacker.example</domain>
        <result>fail</result>
      </spf>
    </auth_results>
  </record>
</feedback>"#;

        let report = parse(xml).unwrap();

        assert_eq!(report.records.len(), 2);
        assert_eq!(report.records[0].row.source_ip, "192.0.2.1");
        assert_eq!(report.records[0].row.count, 1);
        assert_eq!(
            report.records[0].row.policy_evaluated.disposition,
            Disposition::None
        );

        assert_eq!(report.records[1].row.source_ip, "203.0.113.7");
        assert_eq!(report.records[1].row.count, 3);
        assert_eq!(
            report.records[1].row.policy_evaluated.disposition,
            Disposition::Quarantine
        );
        assert_eq!(
            report.records[1].row.policy_evaluated.dkim,
            DmarcResult::Fail
        );
    }

    #[test]
    fn parse_multiple_dkim_spf_auth_results() {
        let xml = r#"<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>Reporter</org_name>
    <email>r@reporter.example</email>
    <report_id>multi-auth-001</report_id>
    <date_range><begin>0</begin><end>86400</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <p>none</p>
    <sp>none</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.1</source_ip>
      <count>1</count>
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
      <dkim>
        <domain>example.com</domain>
        <selector>key1</selector>
        <result>pass</result>
      </dkim>
      <dkim>
        <domain>example.com</domain>
        <selector>key2</selector>
        <result>fail</result>
      </dkim>
      <spf>
        <domain>example.com</domain>
        <scope>helo</scope>
        <result>pass</result>
      </spf>
      <spf>
        <domain>example.com</domain>
        <scope>mfrom</scope>
        <result>pass</result>
      </spf>
    </auth_results>
  </record>
</feedback>"#;

        let report = parse(xml).unwrap();
        let auth = &report.records[0].auth_results;

        assert_eq!(auth.dkim.len(), 2);
        assert_eq!(auth.dkim[0].selector, Some("key1".to_string()));
        assert_eq!(auth.dkim[0].result, DkimResult::Pass);
        assert_eq!(auth.dkim[1].selector, Some("key2".to_string()));
        assert_eq!(auth.dkim[1].result, DkimResult::Fail);

        assert_eq!(auth.spf.len(), 2);
        assert_eq!(auth.spf[0].scope, Some(SpfDomainScope::Helo));
        assert_eq!(auth.spf[1].scope, Some(SpfDomainScope::Mfrom));
    }

    #[test]
    fn parse_alignment_modes() {
        let xml_relaxed = r#"<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>R</org_name><email>r@r.example</email>
    <report_id>r1</report_id>
    <date_range><begin>0</begin><end>1</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>none</p><sp>none</sp><pct>100</pct>
  </policy_published>
  <record>
    <row><source_ip>192.0.2.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><envelope_from>example.com</envelope_from><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"#;

        let report = parse(xml_relaxed).unwrap();
        assert_eq!(report.policy_published.adkim, Some(AlignmentMode::Relaxed));
        assert_eq!(report.policy_published.aspf, Some(AlignmentMode::Relaxed));

        let xml_strict = xml_relaxed
            .replace("<adkim>r</adkim>", "<adkim>s</adkim>")
            .replace("<aspf>r</aspf>", "<aspf>s</aspf>");

        let report = parse(&xml_strict).unwrap();
        assert_eq!(report.policy_published.adkim, Some(AlignmentMode::Strict));
        assert_eq!(report.policy_published.aspf, Some(AlignmentMode::Strict));
    }

    #[test]
    fn parse_empty_alignment_modes() {
        let xml = r#"<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>R</org_name><email>r@r.example</email>
    <report_id>r1</report_id>
    <date_range><begin>0</begin><end>1</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim></adkim>
    <aspf></aspf>
    <p>none</p><sp>none</sp><pct>100</pct>
  </policy_published>
  <record>
    <row><source_ip>192.0.2.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><envelope_from>example.com</envelope_from><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"#;

        let report = parse(xml).unwrap();
        assert!(report.policy_published.adkim.is_none());
        assert!(report.policy_published.aspf.is_none());
    }

    #[test]
    fn parse_all_dkim_results() {
        let results = [
            ("none", DkimResult::None),
            ("pass", DkimResult::Pass),
            ("fail", DkimResult::Fail),
            ("policy", DkimResult::Policy),
            ("neutral", DkimResult::Neutral),
            ("temperror", DkimResult::Temperror),
            ("permerror", DkimResult::Permerror),
        ];

        for (s, expected) in results {
            let xml = format!(
                r#"<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>R</org_name><email>r@r.example</email>
    <report_id>r1</report_id>
    <date_range><begin>0</begin><end>1</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p><sp>none</sp><pct>100</pct></policy_published>
  <record>
    <row><source_ip>192.0.2.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><envelope_from>example.com</envelope_from><header_from>example.com</header_from></identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><result>{s}</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>"#
            );
            let report = parse(&xml).unwrap();
            assert_eq!(
                report.records[0].auth_results.dkim[0].result, expected,
                "failed for DKIM result '{s}'"
            );
        }
    }

    #[test]
    fn parse_all_spf_results() {
        let results = [
            ("none", SpfResult::None),
            ("neutral", SpfResult::Neutral),
            ("pass", SpfResult::Pass),
            ("fail", SpfResult::Fail),
            ("softfail", SpfResult::Softfail),
            ("temperror", SpfResult::Temperror),
            ("permerror", SpfResult::Permerror),
        ];

        for (s, expected) in results {
            let xml = format!(
                r#"<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>R</org_name><email>r@r.example</email>
    <report_id>r1</report_id>
    <date_range><begin>0</begin><end>1</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p><sp>none</sp><pct>100</pct></policy_published>
  <record>
    <row><source_ip>192.0.2.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><envelope_from>example.com</envelope_from><header_from>example.com</header_from></identifiers>
    <auth_results>
      <spf><domain>example.com</domain><result>{s}</result></spf>
    </auth_results>
  </record>
</feedback>"#
            );
            let report = parse(&xml).unwrap();
            assert_eq!(
                report.records[0].auth_results.spf[0].result, expected,
                "failed for SPF result '{s}'"
            );
        }
    }

    #[test]
    fn parse_all_policy_overrides() {
        let overrides = [
            ("forwarded", PolicyOverride::Forwarded),
            ("sampled_out", PolicyOverride::SampledOut),
            ("trusted_forwarder", PolicyOverride::TrustedForwarder),
            ("mailing_list", PolicyOverride::MailingList),
            ("local_policy", PolicyOverride::LocalPolicy),
            ("other", PolicyOverride::Other),
        ];

        for (s, expected) in overrides {
            let xml = format!(
                r#"<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>R</org_name><email>r@r.example</email>
    <report_id>r1</report_id>
    <date_range><begin>0</begin><end>1</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p><sp>none</sp><pct>100</pct></policy_published>
  <record>
    <row><source_ip>192.0.2.1</source_ip><count>1</count>
      <policy_evaluated>
        <disposition>none</disposition><dkim>pass</dkim><spf>pass</spf>
        <reason><type>{s}</type></reason>
      </policy_evaluated>
    </row>
    <identifiers><envelope_from>example.com</envelope_from><header_from>example.com</header_from></identifiers>
    <auth_results>
      <spf><domain>example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
</feedback>"#
            );
            let report = parse(&xml).unwrap();
            assert_eq!(
                report.records[0].row.policy_evaluated.reasons[0].reason_type, expected,
                "failed for policy override '{s}'"
            );
        }
    }

    #[test]
    fn parse_all_dispositions() {
        for (s, expected) in [
            ("none", Disposition::None),
            ("quarantine", Disposition::Quarantine),
            ("reject", Disposition::Reject),
        ] {
            let xml = format!(
                r#"<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>R</org_name><email>r@r.example</email>
    <report_id>r1</report_id>
    <date_range><begin>0</begin><end>1</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>{s}</p><sp>{s}</sp><pct>100</pct></policy_published>
  <record>
    <row><source_ip>192.0.2.1</source_ip><count>1</count>
      <policy_evaluated><disposition>{s}</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><envelope_from>example.com</envelope_from><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"#
            );
            let report = parse(&xml).unwrap();
            assert_eq!(report.policy_published.p, expected, "failed for '{s}'");
            assert_eq!(
                report.records[0].row.policy_evaluated.disposition, expected,
                "failed for '{s}'"
            );
        }
    }

    #[test]
    fn parse_multiple_policy_override_reasons() {
        let xml = r#"<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>R</org_name><email>r@r.example</email>
    <report_id>r1</report_id>
    <date_range><begin>0</begin><end>1</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p><sp>none</sp><pct>100</pct></policy_published>
  <record>
    <row><source_ip>192.0.2.1</source_ip><count>1</count>
      <policy_evaluated>
        <disposition>none</disposition><dkim>pass</dkim><spf>pass</spf>
        <reason><type>forwarded</type><comment>via list</comment></reason>
        <reason><type>mailing_list</type></reason>
      </policy_evaluated>
    </row>
    <identifiers><envelope_from>example.com</envelope_from><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"#;

        let report = parse(xml).unwrap();
        let reasons = &report.records[0].row.policy_evaluated.reasons;
        assert_eq!(reasons.len(), 2);
        assert_eq!(reasons[0].reason_type, PolicyOverride::Forwarded);
        assert_eq!(reasons[0].comment, Some("via list".to_string()));
        assert_eq!(reasons[1].reason_type, PolicyOverride::MailingList);
        assert!(reasons[1].comment.is_none());
    }

    #[test]
    fn parse_ipv6_source_ip() {
        let xml = r#"<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>R</org_name><email>r@r.example</email>
    <report_id>r1</report_id>
    <date_range><begin>0</begin><end>1</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p><sp>none</sp><pct>100</pct></policy_published>
  <record>
    <row><source_ip>2001:db8::1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><envelope_from>example.com</envelope_from><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"#;

        let report = parse(xml).unwrap();
        assert_eq!(report.records[0].row.source_ip, "2001:db8::1");
    }

    #[test]
    fn parse_missing_envelope_from() {
        let xml = r#"<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>R</org_name><email>r@r.example</email>
    <report_id>r1</report_id>
    <date_range><begin>0</begin><end>1</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p><sp>none</sp><pct>100</pct></policy_published>
  <record>
    <row><source_ip>192.0.2.1</source_ip><count>1</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>
</feedback>"#;

        let report = parse(xml).unwrap();
        assert!(report.records[0].identifiers.envelope_from.is_none());
        assert_eq!(report.records[0].identifiers.header_from, "example.com");
    }

    #[test]
    fn from_str_trait() {
        let report: Report = MINIMAL_XML.parse().unwrap();
        assert_eq!(report.report_metadata.org_name, "Acme");
    }

    #[test]
    fn try_from_str_trait() {
        let report = Report::try_from(MINIMAL_XML).unwrap();
        assert_eq!(report.report_metadata.org_name, "Acme");
    }

    #[test]
    fn try_from_bytes_trait() {
        let report = Report::try_from(MINIMAL_XML.as_bytes()).unwrap();
        assert_eq!(report.report_metadata.org_name, "Acme");
    }

    #[test]
    fn parse_bytes_function() {
        let report = parse_bytes(MINIMAL_XML.as_bytes()).unwrap();
        assert_eq!(report.report_metadata.org_name, "Acme");
    }

    #[test]
    fn error_on_invalid_xml() {
        let result = parse("<not-valid-dmarc/>");
        assert!(result.is_err());
    }

    #[test]
    fn error_on_invalid_utf8_bytes() {
        let result = parse_bytes(&[0xFF, 0xFE]);
        assert!(matches!(result, Err(Error::Utf8(_))));
    }

    #[test]
    fn display_alignment_mode() {
        assert_eq!(AlignmentMode::Relaxed.to_string(), "r");
        assert_eq!(AlignmentMode::Strict.to_string(), "s");
    }

    #[test]
    fn display_disposition() {
        assert_eq!(Disposition::None.to_string(), "none");
        assert_eq!(Disposition::Quarantine.to_string(), "quarantine");
        assert_eq!(Disposition::Reject.to_string(), "reject");
    }

    #[test]
    fn display_dmarc_result() {
        assert_eq!(DmarcResult::Pass.to_string(), "pass");
        assert_eq!(DmarcResult::Fail.to_string(), "fail");
    }

    #[test]
    fn display_dkim_result() {
        assert_eq!(DkimResult::None.to_string(), "none");
        assert_eq!(DkimResult::Pass.to_string(), "pass");
        assert_eq!(DkimResult::Fail.to_string(), "fail");
        assert_eq!(DkimResult::Policy.to_string(), "policy");
        assert_eq!(DkimResult::Neutral.to_string(), "neutral");
        assert_eq!(DkimResult::Temperror.to_string(), "temperror");
        assert_eq!(DkimResult::Permerror.to_string(), "permerror");
    }

    #[test]
    fn display_spf_result() {
        assert_eq!(SpfResult::None.to_string(), "none");
        assert_eq!(SpfResult::Neutral.to_string(), "neutral");
        assert_eq!(SpfResult::Pass.to_string(), "pass");
        assert_eq!(SpfResult::Fail.to_string(), "fail");
        assert_eq!(SpfResult::Softfail.to_string(), "softfail");
        assert_eq!(SpfResult::Temperror.to_string(), "temperror");
        assert_eq!(SpfResult::Permerror.to_string(), "permerror");
    }

    #[test]
    fn display_spf_domain_scope() {
        assert_eq!(SpfDomainScope::Helo.to_string(), "helo");
        assert_eq!(SpfDomainScope::Mfrom.to_string(), "mfrom");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Aggregate
    // ──────────────────────────────────────────────────────────────────────────

    fn report_with(report_id: &str, begin: i64, end: i64, counts: &[u64]) -> Report {
        let records: String = counts
            .iter()
            .map(|c| {
                format!(
                    r#"<record>
    <row><source_ip>192.0.2.1</source_ip><count>{c}</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><envelope_from>example.com</envelope_from><header_from>example.com</header_from></identifiers>
    <auth_results><spf><domain>example.com</domain><result>pass</result></spf></auth_results>
  </record>"#
                )
            })
            .collect();

        let xml = format!(
            r#"<?xml version="1.0"?>
<feedback>
  <report_metadata>
    <org_name>R</org_name><email>r@r.example</email>
    <report_id>{report_id}</report_id>
    <date_range><begin>{begin}</begin><end>{end}</end></date_range>
  </report_metadata>
  <policy_published><domain>example.com</domain><p>none</p><sp>none</sp><pct>100</pct></policy_published>
  {records}
</feedback>"#
        );
        parse(&xml).unwrap()
    }

    #[test]
    fn aggregate_empty() {
        let agg = Aggregate::from_reports(vec![]);
        assert_eq!(agg.records().count(), 0);
        assert_eq!(agg.total_messages(), 0);
        assert_eq!(agg.date_span(), None);
    }

    #[test]
    fn aggregate_single_report() {
        let agg = Aggregate::from_reports(vec![report_with("r1", 100, 200, &[3, 5])]);
        assert_eq!(agg.records().count(), 2);
        assert_eq!(agg.total_messages(), 8);
        assert_eq!(agg.date_span(), Some((100, 200)));
    }

    #[test]
    fn aggregate_total_messages_sums_across_reports() {
        let agg = Aggregate::from_reports(vec![
            report_with("r1", 0, 1, &[1, 2]),
            report_with("r2", 0, 1, &[4]),
            report_with("r3", 0, 1, &[10, 20, 30]),
        ]);
        assert_eq!(agg.total_messages(), 1 + 2 + 4 + 10 + 20 + 30);
    }

    #[test]
    fn aggregate_date_span_picks_earliest_begin_and_latest_end() {
        let agg = Aggregate::from_reports(vec![
            report_with("r1", 500, 600, &[1]),
            report_with("r2", 100, 200, &[1]),
            report_with("r3", 300, 900, &[1]),
        ]);
        assert_eq!(agg.date_span(), Some((100, 900)));
    }

    #[test]
    fn aggregate_records_pair_with_source_report() {
        let agg = Aggregate::from_reports(vec![
            report_with("r1", 0, 1, &[1, 2]),
            report_with("r2", 0, 1, &[3]),
        ]);
        let pairs: Vec<(&str, u64)> = agg
            .records()
            .map(|(r, rec)| (r.report_metadata.report_id.as_str(), rec.row.count))
            .collect();
        assert_eq!(pairs, vec![("r1", 1), ("r1", 2), ("r2", 3)]);
    }

    #[test]
    fn aggregate_from_vec_via_into() {
        let reports = vec![report_with("r1", 0, 1, &[7])];
        let agg: Aggregate = reports.into();
        assert_eq!(agg.total_messages(), 7);
    }

    #[test]
    fn display_policy_override() {
        assert_eq!(PolicyOverride::Forwarded.to_string(), "forwarded");
        assert_eq!(PolicyOverride::SampledOut.to_string(), "sampled_out");
        assert_eq!(
            PolicyOverride::TrustedForwarder.to_string(),
            "trusted_forwarder"
        );
        assert_eq!(PolicyOverride::MailingList.to_string(), "mailing_list");
        assert_eq!(PolicyOverride::LocalPolicy.to_string(), "local_policy");
        assert_eq!(PolicyOverride::Other.to_string(), "other");
    }
}
