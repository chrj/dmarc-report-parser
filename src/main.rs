use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use dmarc_report_parser::{Aggregate, Report};

mod render;

// ──────────────────────────────────────────────────────────────────────────────
// CLI definition
// ──────────────────────────────────────────────────────────────────────────────

/// Display DMARC aggregate reports in the terminal, as HTML, or as Markdown.
///
/// Pass multiple files to render them as a single aggregate view with a
/// combined records table.
#[derive(Parser)]
#[command(name = "dmarc-report", version, about)]
struct Cli {
    /// One or more DMARC report files (.xml, .xml.gz, .zip, or .gz).
    #[arg(required = true, num_args = 1..)]
    files: Vec<PathBuf>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = Format::Terminal)]
    format: Format,

    /// Write output to a file instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    /// Colorized terminal output.
    Terminal,
    /// Standalone HTML with embedded styles.
    Html,
    /// Markdown table.
    Markdown,
}

// ──────────────────────────────────────────────────────────────────────────────
// Entry point
// ──────────────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let reports: Vec<Report> = cli
        .files
        .iter()
        .map(|path| load_report(path).map_err(|e| format!("{}: {e}", path.display())))
        .collect::<Result<_, _>>()?;

    let rendered = if reports.len() == 1 {
        let report = &reports[0];
        match cli.format {
            Format::Terminal => render::terminal(report),
            Format::Html => render::html(report),
            Format::Markdown => render::markdown(report),
        }
    } else {
        let agg = Aggregate::from_reports(reports);
        match cli.format {
            Format::Terminal => render::terminal_aggregate(&agg),
            Format::Html => render::html_aggregate(&agg),
            Format::Markdown => render::markdown_aggregate(&agg),
        }
    };

    match cli.output {
        Some(path) => {
            fs::write(&path, &rendered)
                .map_err(|e| format!("Error writing to {}: {e}", path.display()))?;
            eprintln!("Report written to {}", path.display());
        }
        None => print!("{rendered}"),
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// File loading & extraction
// ──────────────────────────────────────────────────────────────────────────────

/// The largest report the CLI reads after decompression. Real aggregate
/// reports are a few MB at most. Reports come from other domains, so a small
/// compressed file must not be able to use up all memory.
const MAX_REPORT_BYTES: u64 = 64 * 1024 * 1024;

fn load_report(path: &PathBuf) -> Result<Report, String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let xml_bytes = match ext.as_str() {
        "zip" => extract_xml_from_zip(path, MAX_REPORT_BYTES)
            .map_err(|e| format!("Failed to read zip: {e}"))?,
        "gz" => decompress_gzip(path, MAX_REPORT_BYTES)
            .map_err(|e| format!("Failed to decompress gzip: {e}"))?,
        _ => fs::read(path).map_err(|e| format!("Failed to read file: {e}"))?,
    };

    let xml =
        std::str::from_utf8(&xml_bytes).map_err(|e| format!("File is not valid UTF-8: {e}"))?;

    dmarc_report_parser::parse(xml).map_err(|e| format!("Failed to parse DMARC report: {e}"))
}

fn extract_xml_from_zip(path: &PathBuf, limit: u64) -> Result<Vec<u8>, io::Error> {
    let file = fs::File::open(path)?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    for i in 0..archive.len() {
        let entry = archive
            .by_index(i)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let name = entry
            .name()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
            .to_lowercase();
        if name.ends_with(".xml") {
            return read_limited(entry, limit);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "No .xml file found in the zip archive",
    ))
}

fn decompress_gzip(path: &PathBuf, limit: u64) -> Result<Vec<u8>, io::Error> {
    let file = fs::File::open(path)?;
    read_limited(flate2::read::GzDecoder::new(file), limit)
}

/// Reads all of `reader`, but fails with `InvalidData` when it holds more
/// than `limit` bytes.
fn read_limited(reader: impl Read, limit: u64) -> Result<Vec<u8>, io::Error> {
    let mut buf = Vec::new();
    reader.take(limit + 1).read_to_end(&mut buf)?;
    if buf.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("data is larger than {limit} bytes when decompressed"),
        ));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn read_limited_accepts_input_up_to_the_limit() {
        let cases: [(&[u8], u64); 3] = [(b"", 4), (b"abc", 4), (b"abcd", 4)];
        for (input, limit) in cases {
            let got = read_limited(input, limit).unwrap();
            assert_eq!(got, input);
        }
    }

    #[test]
    fn read_limited_rejects_input_over_the_limit() {
        let err = read_limited(&b"abcde"[..], 4).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            err.to_string(),
            "data is larger than 4 bytes when decompressed"
        );
    }

    #[test]
    fn gzip_over_the_limit_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bomb.xml.gz");
        let mut encoder = flate2::write::GzEncoder::new(
            fs::File::create(&path).unwrap(),
            flate2::Compression::best(),
        );
        encoder.write_all(&[b'a'; 1024]).unwrap();
        encoder.finish().unwrap();

        let err = decompress_gzip(&path, 1023).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(decompress_gzip(&path, 1024).is_ok());
    }

    #[test]
    fn zip_entry_over_the_limit_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bomb.zip");
        let mut writer = zip::ZipWriter::new(fs::File::create(&path).unwrap());
        writer
            .start_file("report.xml", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&[b'a'; 1024]).unwrap();
        writer.finish().unwrap();

        let err = extract_xml_from_zip(&path, 1023).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(extract_xml_from_zip(&path, 1024).is_ok());
    }
}
