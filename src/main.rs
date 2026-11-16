use chrono::NaiveDate;
use chrono::NaiveDateTime;
use chrono::NaiveTime;
use clap::Parser;
use clap::Subcommand;

use crate::crawler::LogSource;
use crate::crawler::Crawler;

mod crawler;
mod dns_resolver;

#[derive(Parser, Debug)]
#[command(version, about = "Certificate Transparency Logs Utility")]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Ctl {
        /// Start date/time (inclusive)
        /// Format: YYYY-MM-DD or YYYY-MM-DDTHH:MM
        #[arg(value_parser = parse_date, short = 's', long = "start-date", conflicts_with_all = ["search_timestamp", "start_index", "end_index"])]
        start_date: Option<NaiveDateTime>,

        /// End date/time (exclusive)
        /// Format: YYYY-MM-DD or YYYY-MM-DDTHH:MM
        #[arg(value_parser = parse_date, short = 'e', long = "end-date", requires = "start_date", conflicts_with_all = ["search_timestamp", "start_index", "end_index"])]
        end_date: Option<NaiveDateTime>,

        /// Path to txt file containing CT log URLs
        /// Format: Each line should contain a single CT log URL
        #[arg(short = 'f', long = "url-file", conflicts_with = "ct_log_url")]
        url_file_path: Option<String>,

        /// CT log URL
        #[arg(short = 'u', long = "ct-log-url", conflicts_with = "url_file_path")]
        ct_log_url: Option<String>,

        /// Search timestamp index
        /// Format: YYYY-MM-DD or YYYY-MM-DDTHH:MM
        #[arg(value_parser = parse_date, short = 't', long = "search-timestamp", conflicts_with_all = ["start_date", "end_date", "start_index", "end_index"])]
        search_timestamp: Option<NaiveDateTime>,

        /// Start index for fetching entries
        /// Format: u64
        /// Requires: end_index
        #[arg(
            short = 'i',
            long = "start-index",
            requires = "end_index",
            conflicts_with_all = ["start_date", "end_date", "search_timestamp"]
        )]
        start_index: Option<u64>,

        /// End index for fetching entries
        /// Format: u64
        /// Requires: start_index
        #[arg(
            short = 'j',
            long = "end-index",
            requires = "start_index",
            // conflicts_with = "start_date, end_date, search_timestamp"
            conflicts_with_all = ["start_date", "end_date", "search_timestamp"]
        )]
        end_index: Option<u64>,
    },
    Dns,
}

fn parse_date(date_str: &str) -> Result<NaiveDateTime, String> {
    if let Ok(date) = NaiveDateTime::parse_from_str(date_str, "%Y-%m-%dT%H:%M") {
        return Ok(date);
    }

    if let Ok(date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
        return Ok(date.and_time(NaiveTime::MIN));
    }

    Err(format!(
        "Invalid date/time '{date_str}', only YYYY-MM-DD or YYYY-MM-DDTHH:MM"
    ))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    println!(
        r#"   ____ _____ _    _   _ _   _ _ 
  / ___|_   _| |  | | | | |_(_) |
 | |     | | | |  | | | | __| | |
 | |___  | | | |__| |_| | |_| | |
  \____| |_| |_____\___/ \__|_|_|
                                 "#
    );
    println!("Certificate Transparency Logs Utility (CTLU)");

    match args.command {
        Commands::Ctl {
            start_date,
            end_date,
            url_file_path,
            ct_log_url,
            start_index,
            end_index,
            search_timestamp,
        } => {
            let log_source = if let Some(path) = url_file_path {
                LogSource::UrlTxtFile(path)
            } else if let Some(url) = ct_log_url {
                LogSource::CtLogUrl(url)
            } else {
                LogSource::Gstatic
            };

            let fetch_mode = if let Some(start_date) = start_date {
                crawler::FetchMode::DateRange {
                    start_date,
                    end_date,
                }
            } else if let Some(timestamp) = search_timestamp {
                crawler::FetchMode::SearchTimestamp { timestamp }
            } else if let (Some(start_index), Some(end_index)) = (start_index, end_index) {
                crawler::FetchMode::IndexRange {
                    start_index,
                    end_index,
                }
            } else {
                crawler::FetchMode::Monitor
            };

            let parse_mode = crawler::ParseMode::Domain;
            let output_mode = crawler::OutputMode::Sqlite;

            let crawler = Crawler::new(fetch_mode, log_source, parse_mode, output_mode);
            let _ = crawler.run().await;

            // let crawler = Crawler::new(start_date, end_date, url_file_path, ct_log_url);
            // let _ = crawler.run().await;
        }
        Commands::Dns => {
            println!("Starting DNS resolution...");
            if let Err(e) = dns_resolver::resolve_domains_sqlite("nothing".to_string()).await {
                eprintln!("DNS resolution failed: {e}");
            }
        }
    }

    Ok(())
}
