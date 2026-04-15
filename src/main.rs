use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use dmarc_report_parser::Report;

mod render;

// ──────────────────────────────────────────────────────────────────────────────
// CLI definition
// ──────────────────────────────────────────────────────────────────────────────

/// Display DMARC aggregate reports in the terminal, as HTML, or as Markdown.
#[derive(Parser)]
#[command(name = "dmarc-report", version, about)]
struct Cli {
    /// Path to a DMARC report file (.xml, .xml.gz, .zip, or .gz).
    file: PathBuf,

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
    let report = load_report(&cli.file)?;

    let rendered = match cli.format {
        Format::Terminal => render::terminal(&report),
        Format::Html => render::html(&report),
        Format::Markdown => render::markdown(&report),
    };

    match cli.output {
        Some(path) => {
            fs::write(&path, &rendered).map_err(|e| format!("Error writing to {}: {e}", path.display()))?;
            eprintln!("Report written to {}", path.display());
        }
        None => print!("{rendered}"),
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// File loading & extraction
// ──────────────────────────────────────────────────────────────────────────────

fn load_report(path: &PathBuf) -> Result<Report, String> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let xml_bytes = match ext.as_str() {
        "zip" => extract_xml_from_zip(path).map_err(|e| format!("Failed to read zip: {e}"))?,
        "gz" => decompress_gzip(path).map_err(|e| format!("Failed to decompress gzip: {e}"))?,
        _ => fs::read(path).map_err(|e| format!("Failed to read file: {e}"))?,
    };

    let xml =
        std::str::from_utf8(&xml_bytes).map_err(|e| format!("File is not valid UTF-8: {e}"))?;

    dmarc_report_parser::parse(xml).map_err(|e| format!("Failed to parse DMARC report: {e}"))
}

fn extract_xml_from_zip(path: &PathBuf) -> Result<Vec<u8>, io::Error> {
    let file = fs::File::open(path)?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let name = entry.name().to_lowercase();
        if name.ends_with(".xml") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            return Ok(buf);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "No .xml file found in the zip archive",
    ))
}

fn decompress_gzip(path: &PathBuf) -> Result<Vec<u8>, io::Error> {
    let file = fs::File::open(path)?;
    let mut decoder = flate2::read::GzDecoder::new(file);
    let mut buf = Vec::new();
    decoder.read_to_end(&mut buf)?;
    Ok(buf)
}
