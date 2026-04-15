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
        .stderr(predicate::str::contains("Error: Failed to read file"));
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
