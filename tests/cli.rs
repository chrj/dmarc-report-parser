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
