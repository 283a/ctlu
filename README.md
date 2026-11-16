# CTLU - Certificate Transparency Log Utility

`ctlu` is a command-line utility for the Certificate Transparency (CT) logs.
It can fetch CT log entries by date range or index range, locate the entry index nearest to a timestamp or monitor the CT log/s.
For either a single log or multiple logs provided with a txt file or create a log list of active logs from the chrome log lists.
It can also resolve domains, collected, using the public cloudflare or google resolver.  

Supports CT version 1 from the RFC 6962, version 2 support planned.

## Usage

```text
ctlu <COMMAND>
```

Available commands:

- `ctl` — query/crawl one or more Certificate Transparency logs
- `dns` — run DNS resolving for domains
- `help` — help

```bash
ctlu --help
ctlu ctl --help
```

### Crawler

```text
ctlu ctl [OPTIONS]
```

Choose at most one source option:

| Option | Description |
| --- | --- |
| `-u, --ct-log-url <URL>` | Single CT log URL |
| `-f, --url-file <PATH>` | CT log URLs from a text file, one URL per line |
| `None` | Chrome log list, given date or now

Example URL file:

```text
https://ct.googleapis.com/logs/us1/argon2026h1/
https://ct.cloudflare.com/logs/nimbus2026/
```

Chrome log lists are available: 
- https://googlechrome.github.io/CertificateTransparency/log_lists.html
- https://www.gstatic.com/ct/log_list/v3/log_list.json
- https://www.gstatic.com/ct/log_list/v3/all_logs_list.json


The `ctl` command has three mutually exclusive modes.

Fetch date range:

Use `-s` \ `--start-date`  and, optionally, `-e` \ `--end-date`:

```bash
ctlu ctl --ct-log-url https://<log server> --start-date 2026-08-01 --end-date 2026-08-02
```

- The start date/time is inclusive.
- The end date/time is exclusive.
- `--end-date` requires `--start-date`.

Search timestamp/datetime UTC index.

Use `-t` \ `--search-timestamp`:

```bash
ctlu ctl --ct-log-url https://<log server> --search-timestamp 2026-08-01T12:30
```

Fetch index range:

Use both `-i` \ `--start-index` and `-j` \ `--end-index`:

```bash
ctlu ctl --ct-log-url https://<log server> --start-index 1000 --end-index 1100
```

Options:

| Short | Long | Value | Notes |
| --- | --- | --- | --- |
| `-s` | `--start-date` | Date/time | Inclusive; conflicts with timestamp and index modes. |
| `-e` | `--end-date` | Date/time | Exclusive; requires `--start-date`. |
| `-t` | `--search-timestamp` | Date/time | Conflicts with date-range and index modes. |
| `-i` | `--start-index` | `u64` | Requires `--end-index`. |
| `-j` | `--end-index` | `u64` | Requires `--start-index`. |
| `-u` | `--ct-log-url` | URL | Conflicts with `--url-file`. |
| `-f` | `--url-file` | Path | Conflicts with `--ct-log-url`. |

Accepted date/time formats (UTC):

YYYY-MM-DD and YYYY-MM-DDTHH:MM

Examples:

2026-08-01

2026-08-01T12:30

### DNS

```text
ctlu dns
```

Work in  progress.

### More examples

Fetch CT logs from file for one day:

```bash
ctlu ctl -f ct-logs.txt -s 2026-08-01 -e 2026-08-02
```

Fetch from a starting date without specifying an end date, all chrome logs:

```bash
ctlu ctl -s 2026-08-01
```

## Output

Sqlite

## Build


```bash
cargo build --release
```

The executable is in `target/release/`.

In development:

```bash
cargo run -- --help
```

## Work in Progress

- parser modes
- output modes

## Related Repositories

- https://github.com/mpalmer/scrape-ct-log
- https://github.com/google/certificate-transparency-community-site/blob/master/docs/google/fetch-logs.md#api-and-server-behaviours
- https://github.com/jonaslejon/ct-monitor


## Architecture

The utility functions support a modular pipeline architecture, with individual configurable parts.

Crawler:

fetcher -> parser -> writer

DNS:

reader -> resolver -> writer

## CT logs:

RFC 6962:

### STH
tree_size: 
timestamp:
sha256_root_hash:	
tree_head_signature:	

RFC 

WIP





