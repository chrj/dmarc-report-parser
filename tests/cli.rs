use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn file_does_not_exist() {
    let mut cmd = Command::cargo_bin("dmarc-report").unwrap();
    cmd.arg("tests/fixtures/does-not-exist.xml");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("does-not-exist.xml"))
        .stderr(predicate::str::contains("Failed to read file"));
}

#[test]
fn minimal_xml_to_stdout_terminal() {
    let mut cmd = Command::cargo_bin("dmarc-report").unwrap();
    cmd.arg("tests/fixtures/minimal.xml");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("DMARC Aggregate Report"))
        .stdout(predicate::str::contains("Acme"));
}

#[test]
fn minimal_xml_to_stdout_markdown() {
    let mut cmd = Command::cargo_bin("dmarc-report").unwrap();
    cmd.arg("tests/fixtures/minimal.xml")
        .arg("--format")
        .arg("markdown");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("| Source IP |"));
}

#[test]
fn zip_with_xml_entry_is_parsed() {
    // The fixture holds minimal.xml as "MINIMAL.XML" to cover the
    // case-insensitive match on the entry name.
    let mut cmd = Command::cargo_bin("dmarc-report").unwrap();
    cmd.arg("tests/fixtures/minimal.zip")
        .arg("--format")
        .arg("markdown");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Acme"))
        .stdout(predicate::str::contains("| Source IP |"));
}

#[test]
fn zip_without_xml_entry_fails() {
    let mut cmd = Command::cargo_bin("dmarc-report").unwrap();
    cmd.arg("tests/fixtures/no-xml.zip");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("no-xml.zip"))
        .stderr(predicate::str::contains(
            "Failed to read zip: No .xml file found in the zip archive",
        ));
}

#[test]
fn aggregate_two_files_markdown() {
    let mut cmd = Command::cargo_bin("dmarc-report").unwrap();
    cmd.arg("tests/fixtures/minimal.xml")
        .arg("tests/fixtures/second.xml")
        .arg("--format")
        .arg("markdown");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("# DMARC Aggregate Report"))
        .stdout(predicate::str::contains("**Reports:** 2"))
        .stdout(predicate::str::contains("**Total Messages:** 7"))
        .stdout(predicate::str::contains("Acme"))
        .stdout(predicate::str::contains("Globex"))
        .stdout(predicate::str::contains("20130901.r.acme.example"))
        .stdout(predicate::str::contains("20130902.r.globex.example"))
        .stdout(predicate::str::contains("| Report |"));
}

#[test]
fn aggregate_two_files_terminal() {
    let mut cmd = Command::cargo_bin("dmarc-report").unwrap();
    cmd.arg("tests/fixtures/minimal.xml")
        .arg("tests/fixtures/second.xml");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("DMARC Aggregate Report"))
        .stdout(predicate::str::contains("Reports        : 2"))
        .stdout(predicate::str::contains("Total Messages : 7"))
        .stdout(predicate::str::contains("Acme"))
        .stdout(predicate::str::contains("Globex"));
}

#[test]
fn aggregate_two_files_html() {
    let dir = tempdir().expect("Failed to create temp dir");
    let output_path = dir.path().join("agg.html");

    let mut cmd = Command::cargo_bin("dmarc-report").unwrap();
    cmd.arg("tests/fixtures/minimal.xml")
        .arg("tests/fixtures/second.xml")
        .arg("--format")
        .arg("html")
        .arg("--output")
        .arg(&output_path);

    cmd.assert().success();

    let content = fs::read_to_string(&output_path).expect("Failed to read output file");
    // Single valid HTML document (one DOCTYPE, not concatenated docs).
    assert_eq!(content.matches("<!DOCTYPE html>").count(), 1);
    assert!(content.contains("DMARC Aggregate Report"));
    assert!(content.contains("Acme"));
    assert!(content.contains("Globex"));
    assert!(content.contains("<th>Report</th>"));
}

#[test]
fn aggregate_one_failing_file_reports_path() {
    let mut cmd = Command::cargo_bin("dmarc-report").unwrap();
    cmd.arg("tests/fixtures/minimal.xml")
        .arg("tests/fixtures/does-not-exist.xml");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("does-not-exist.xml"));
}

#[test]
fn minimal_xml_to_file_html() {
    let dir = tempdir().expect("Failed to create temp dir");
    let output_path = dir.path().join("report.html");

    let mut cmd = Command::cargo_bin("dmarc-report").unwrap();
    cmd.arg("tests/fixtures/minimal.xml")
        .arg("--format")
        .arg("html")
        .arg("--output")
        .arg(&output_path);

    cmd.assert().success();

    assert!(output_path.exists());
    let content = fs::read_to_string(output_path).expect("Failed to read output file");
    assert!(content.contains("<!DOCTYPE html>"));
    assert!(content.contains("Acme"));
}

#[test]
fn html_period_separator_is_not_double_escaped() {
    // Regression: dl_row escapes its value, so callers must pass plain text.
    // Previously the Period row used the "&rarr;" HTML entity, which got
    // re-escaped to "&amp;rarr;" and rendered literally in the browser.
    let dir = tempdir().expect("Failed to create temp dir");
    let output_path = dir.path().join("report.html");

    let mut cmd = Command::cargo_bin("dmarc-report").unwrap();
    cmd.arg("tests/fixtures/minimal.xml")
        .arg("--format")
        .arg("html")
        .arg("--output")
        .arg(&output_path);

    cmd.assert().success();

    let content = fs::read_to_string(&output_path).expect("Failed to read output file");
    assert!(
        !content.contains("&amp;rarr;"),
        "Period separator was double-escaped: {content}"
    );
    assert!(
        content.contains("<dt>Period</dt>") && content.contains('→'),
        "Expected a Period row containing a Unicode arrow"
    );
}

#[test]
fn gzip_over_max_size_fails_with_a_hint() {
    // The fixture expands to 1 MiB + 1 byte.
    let mut cmd = Command::cargo_bin("dmarc-report").unwrap();
    cmd.arg("tests/fixtures/over-1mib.xml.gz")
        .arg("--max-size")
        .arg("1");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("over-1mib.xml.gz"))
        .stderr(predicate::str::contains(
            "Failed to decompress gzip: report is larger than 1 MiB after decompression. \
             To read it, run again with a larger --max-size",
        ));
}

#[test]
fn max_size_of_zero_is_rejected() {
    let mut cmd = Command::cargo_bin("dmarc-report").unwrap();
    cmd.arg("tests/fixtures/minimal.xml")
        .arg("--max-size")
        .arg("0");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("--max-size"));
}
