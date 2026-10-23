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

    /// Largest size in MiB of a compressed report after decompression.
    #[arg(long, value_name = "MIB", default_value_t = 64, value_parser = clap::value_parser!(u64).range(1..))]
    max_size: u64,
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
        .map(|path| load_report(path, cli.max_size).map_err(|e| format!("{}: {e}", path.display())))
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

const MIB: u64 = 1024 * 1024;

/// Reads and parses one report. `max_mib` limits the decompressed size of a
/// zip or gzip report. Reports come from other domains, so a small compressed
/// file must not be able to use up all memory.
fn load_report(path: &PathBuf, max_mib: u64) -> Result<Report, String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let xml_bytes =
        match ext.as_str() {
            "zip" => extract_xml_from_zip(path, max_mib)
                .map_err(|e| format!("Failed to read zip: {e}"))?,
            "gz" => decompress_gzip(path, max_mib)
                .map_err(|e| format!("Failed to decompress gzip: {e}"))?,
            _ => fs::read(path).map_err(|e| format!("Failed to read file: {e}"))?,
        };

    let xml =
        std::str::from_utf8(&xml_bytes).map_err(|e| format!("File is not valid UTF-8: {e}"))?;

    dmarc_report_parser::parse(xml).map_err(|e| format!("Failed to parse DMARC report: {e}"))
}

fn extract_xml_from_zip(path: &PathBuf, max_mib: u64) -> Result<Vec<u8>, io::Error> {
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
            return read_limited(entry, max_mib);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "No .xml file found in the zip archive",
    ))
}

fn decompress_gzip(path: &PathBuf, max_mib: u64) -> Result<Vec<u8>, io::Error> {
    let file = fs::File::open(path)?;
    read_limited(flate2::read::GzDecoder::new(file), max_mib)
}

/// Reads all of `reader`, but fails with `InvalidData` when it holds more
/// than `max_mib` MiB.
fn read_limited(reader: impl Read, max_mib: u64) -> Result<Vec<u8>, io::Error> {
    let limit = max_mib.saturating_mul(MIB);
    let mut buf = Vec::new();
    reader.take(limit.saturating_add(1)).read_to_end(&mut buf)?;
    if buf.len() as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "report is larger than {max_mib} MiB after decompression. \
                 To read it, run again with a larger --max-size"
            ),
        ));
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const ONE_MIB: usize = MIB as usize;

    #[test]
    fn read_limited_accepts_input_up_to_the_limit() {
        for len in [0, 3, ONE_MIB] {
            let input = vec![b'a'; len];
            let got = read_limited(&input[..], 1).unwrap();
            assert_eq!(got.len(), len);
        }
    }

    #[test]
    fn read_limited_rejects_input_over_the_limit() {
        let input = vec![b'a'; ONE_MIB + 1];
        let err = read_limited(&input[..], 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            err.to_string(),
            "report is larger than 1 MiB after decompression. \
             To read it, run again with a larger --max-size"
        );
    }

    #[test]
    fn read_limited_does_not_overflow_on_a_huge_limit() {
        let got = read_limited(&b"abc"[..], u64::MAX).unwrap();
        assert_eq!(got, b"abc");
    }

    #[test]
    fn gzip_over_the_limit_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bomb.xml.gz");
        let mut encoder = flate2::write::GzEncoder::new(
            fs::File::create(&path).unwrap(),
            flate2::Compression::best(),
        );
        encoder.write_all(&vec![b'a'; ONE_MIB + 1]).unwrap();
        encoder.finish().unwrap();

        let err = decompress_gzip(&path, 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(decompress_gzip(&path, 2).is_ok());
    }

    #[test]
    fn zip_entry_over_the_limit_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bomb.zip");
        let mut writer = zip::ZipWriter::new(fs::File::create(&path).unwrap());
        writer
            .start_file("report.xml", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&vec![b'a'; ONE_MIB + 1]).unwrap();
        writer.finish().unwrap();

        let err = extract_xml_from_zip(&path, 1).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(extract_xml_from_zip(&path, 2).is_ok());
    }
}
