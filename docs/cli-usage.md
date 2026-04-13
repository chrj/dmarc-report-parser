# CLI usage

The `dmarc-report` binary is an optional CLI tool for rendering DMARC aggregate
reports in the terminal, as HTML, or as Markdown. It is built when the `cli`
Cargo feature is enabled.

## Installation

```sh
cargo install dmarc-report-parser --features cli
```

## Synopsis

```text
dmarc-report [OPTIONS] <FILE>
```

### Arguments

| Argument | Description |
|----------|-------------|
| `<FILE>` | Path to a DMARC report file (`.xml`, `.xml.gz`, `.gz`, or `.zip`) |

### Options

| Option | Default | Description |
|--------|---------|-------------|
| `-f`, `--format <FORMAT>` | `terminal` | Output format: `terminal`, `html`, or `markdown` |
| `-o`, `--output <FILE>` | stdout | Write rendered output to a file |
| `-h`, `--help` | | Print help information |
| `-V`, `--version` | | Print version |

## Output formats

### Terminal (default)

Produces colorized, human-readable output suitable for viewing in a terminal
emulator. Passing and failing results are highlighted with colors.

```sh
dmarc-report report.xml
```

### HTML

Generates a standalone HTML document with embedded CSS styles. This can be
opened directly in a browser or served from a web server.

```sh
dmarc-report report.xml --format html --output report.html
```

### Markdown

Renders the report as Markdown tables. Useful for pasting into issues, wikis,
or other documentation.

```sh
dmarc-report report.xml.gz --format markdown
```

## Supported input formats

The CLI automatically detects the file format from the file extension:

| Extension | Handling |
|-----------|----------|
| `.xml` | Parsed directly as XML |
| `.gz`, `.xml.gz` | Decompressed with gzip, then parsed |
| `.zip` | The first `.xml` entry is extracted and parsed |

## Examples

```sh
# View a plain XML report in the terminal
dmarc-report report.xml

# View a gzip-compressed report
dmarc-report report.xml.gz

# Extract and view a report from a zip archive
dmarc-report report.zip

# Save an HTML report to disk
dmarc-report report.xml --format html --output report.html

# Pipe Markdown output into another tool
dmarc-report report.xml --format markdown | less
```
