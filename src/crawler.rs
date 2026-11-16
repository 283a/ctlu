use chrono::{NaiveDateTime, TimeZone, Utc};

mod fetcher;
mod parser;
mod writer;

pub enum FetchMode {
    DateRange {
        start_date: NaiveDateTime,
        end_date: Option<NaiveDateTime>,
    },
    SearchTimestamp {
        timestamp: NaiveDateTime,
    },
    IndexRange {
        start_index: u64,
        end_index: u64,
    },
    Monitor,
}

pub enum LogSource {
    UrlTxtFile(String),
    CtLogUrl(String),
    Gstatic,
}

pub enum ParseMode {
    Domain,
    Cert,
}

pub enum OutputMode {
    Txt,
    Sqlite,
}

pub struct Crawler {
    fetch_mode: FetchMode,
    log_source: LogSource,
    parse_mode: ParseMode,
    output_mode: OutputMode,
}

impl Crawler {
    pub fn new(
        fetch_mode: FetchMode,
        log_source: LogSource,
        parse_mode: ParseMode,
        output_mode: OutputMode,
    ) -> Self {
        Self {
            fetch_mode,
            log_source,
            parse_mode,
            output_mode,
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        // TODO: just create a vector of log sources then same api for all
        let fetcher = match &self.log_source {
            LogSource::UrlTxtFile(path) => fetcher::Fetcher::create_from_file(path).await?,
            
            LogSource::CtLogUrl(url) => fetcher::Fetcher::create_from_url(url).await?,
            
            LogSource::Gstatic => {
                let (start_date, end_date) = match &self.fetch_mode {
                    FetchMode::DateRange {
                        start_date,
                        end_date,
                    } => {
                        let end_date = match end_date {
                            Some(date) => Utc.from_local_datetime(&date).single().unwrap(),
                            None => Utc::now(),
                        };
                        let start_date = Utc.from_local_datetime(&start_date).single().unwrap();
                        (start_date, end_date)
                    }
                    _ => (Utc::now(), Utc::now()),
                };

                fetcher::Fetcher::create_gstatic(start_date, end_date).await?
            }
        };

        let fetcher_rx = match &self.fetch_mode {
            FetchMode::DateRange {
                start_date,
                end_date,
            } => {
                let end_date = match end_date {
                    Some(date) => Utc.from_local_datetime(&date).single().unwrap(),
                    None => Utc::now(),
                };
                let start_date = Utc.from_local_datetime(&start_date).single().unwrap();
                let end_date = end_date.timestamp_millis() as u64;
                let start_date = start_date.timestamp_millis() as u64;
                fetcher.start_historic(start_date, end_date).await?
            }
            
            FetchMode::SearchTimestamp { timestamp } => {
                let timestamp = Utc.from_local_datetime(&timestamp).single().unwrap();
                let timestamp = timestamp.timestamp_millis() as u64;
                let _ = fetcher.start_timestamp_search(timestamp).await?;
                return Ok(());
            }
            
            FetchMode::IndexRange {
                start_index,
                end_index,
            } => fetcher.start_index_range(*start_index, *end_index).await?,
            
            FetchMode::Monitor => fetcher.start_monitor().await?,
        };

        fetcher.spawn_reporter().await?;

        let parser_rx = match &self.parse_mode {
            ParseMode::Domain => parser::spawn_domain(fetcher_rx).await?,
            // ParseMode::Cert => parser::spawn_cert(fetcher_rx).await?,
            ParseMode::Cert => {
                eprintln!("Cert parsing is not implemented yet.");
                return Ok(());
            }
        };

        let _ = match &self.output_mode {
            // OutputMode::Txt => writer::output_txt(parser_rx).await?,
            OutputMode::Txt => {
                eprintln!("Txt output is not implemented yet.");
                return Ok(());
            }
            OutputMode::Sqlite => writer::output_sqlite(parser_rx).await?,
        };

        Ok(())
    }
}