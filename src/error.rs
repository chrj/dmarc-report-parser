use thiserror::Error;

/// Errors that can occur while parsing a DMARC aggregate report.
#[derive(Debug, Error)]
pub enum Error {
    /// The XML is malformed or does not conform to the DMARC report schema.
    #[error("failed to parse DMARC report XML: {0}")]
    Parse(#[from] quick_xml::DeError),

    /// The input bytes are not valid UTF-8.
    #[error("input is not valid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}
