use crate::crawler::fetcher;
use crate::crawler::{fetcher::rate_limiter::TokenBucketLimiter, parser};
use anyhow::Context;
use anyhow::anyhow;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use reqwest::{StatusCode, Url};
use serde::{Deserialize, de::Error};
use std::{
    ops::Div,
    sync::{Arc, atomic::AtomicU64},
    time::Duration,
};
use tokio::task::JoinHandle;
use tokio::{
    sync::{
        Semaphore,
        mpsc::{self, Sender},
    },
    time::{Instant, sleep},
};

mod rate_limiter;

#[derive(Debug, Deserialize)]
pub struct LogList {
    pub version: String,
    pub log_list_timestamp: String,
    pub operators: Vec<Operator>,
}

#[derive(Debug, Deserialize)]
pub struct Operator {
    pub name: String,
    pub email: Vec<String>,
    pub logs: Vec<Log>,
    pub tiled_logs: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct Log {
    pub description: String,
    pub log_id: String,
    pub key: String,
    pub url: String,
    pub mmd: u32,
    pub state: State,
    pub temporal_interval: TemporalInterval,
}
#[derive(Debug, Deserialize)]
pub struct State {
    pub usable: Option<Timestamped>,
    pub retired: Option<Timestamped>,
    pub readonly: Option<ReadonlyState>,
}

#[derive(Debug, Deserialize)]
pub struct Timestamped {
    pub timestamp: String,
}

#[derive(Debug, Deserialize)]
pub struct ReadonlyState {
    pub timestamp: String,
    pub final_tree_head: FinalTreeHead,
}

#[derive(Debug, Deserialize)]
pub struct FinalTreeHead {
    pub sha256_root_hash: String,
    pub tree_size: u64,
}

#[derive(Debug, Deserialize)]
pub struct TemporalInterval {
    pub start_inclusive: String,
    pub end_exclusive: String,
}

#[derive(Debug, Deserialize)]
struct Sth {
    tree_size: u64,
    timestamp: u64,
    sha256_root_hash: String,
    tree_head_signature: String,
}

#[derive(Debug, Deserialize)]
struct Entry<'a> {
    leaf_input: &'a [u8],
    // ignore extra_data, do not even parse it
    // extra_data: String,
}

#[derive(Debug, Deserialize)]
struct Entries<'a> {
    #[serde(borrow)]
    entries: Vec<Entry<'a>>,
}

#[derive(Debug)]
struct CTLog {
    url: String,
    http_client: reqwest::Client,
    // do current cursor maybe
    pub start: Arc<AtomicU64>,
    pub end: Arc<AtomicU64>,
    pub current_pos: Arc<AtomicU64>,
    pub fetch_count: Arc<AtomicU64>,
}

#[derive(Debug)]
struct CTLogState {
    pub url: String,
    pub start: Arc<AtomicU64>,
    pub end: Arc<AtomicU64>,
    pub current_pos: Arc<AtomicU64>,
    pub fetch_count: Arc<AtomicU64>,
    pub start_plain: u64,
    pub end_plain: u64,
}

impl CTLog {
    fn new(url: String, http_client: reqwest::Client) -> Self {
        Self {
            url,
            http_client,
            start: Arc::new(AtomicU64::new(0)),
            end: Arc::new(AtomicU64::new(0)),
            current_pos: Arc::new(AtomicU64::new(0)),
            fetch_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// date in milliseconds since epoch
    async fn download_to_tree_size(
        &self,
        tx: Sender<Bytes>,
        start_date: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // either do self: Arc<Self> /&Arc<Self> and clone arc pointer to self in spawn if desierd to spawn more tasks or take ownership of self and consume it
        // https://users.rust-lang.org/t/access-self-methods-from-within-async-task/121832

        let url = self.url.clone();
        let http_client = self.http_client.clone();
        // let start_date = start_date;
        let start_reference = self.start.clone();
        let end_reference = self.end.clone();
        let current_pos_reference = self.current_pos.clone();
        let fetcher_count_reference = self.fetch_count.clone();

        tokio::spawn(async move {
            let init_bytes = Bytes::new();

            // need to to use channel once, otherwise closes one parser
            let _ = tx.send(init_bytes).await;

            let rate_limiter = TokenBucketLimiter::new(10.0, 5.0);

            let signed_tree_head = match fetch_sth(&url, &http_client, &rate_limiter).await {
                Ok(sth) => sth,
                Err(_) => {
                    return;
                }
            };

            let start_index = match search_date(
                &url,
                &http_client,
                &rate_limiter,
                start_date,
                &signed_tree_head,
            )
            .await
            {
                Ok(s_i) => s_i,
                Err(_) => {
                    return;
                }
            };

            start_reference.store(start_index as u64, std::sync::atomic::Ordering::Relaxed);
            end_reference.store(
                signed_tree_head.tree_size,
                std::sync::atomic::Ordering::Relaxed,
            );
            current_pos_reference.store(start_index as u64, std::sync::atomic::Ordering::Relaxed);

            println!("Log: {}, start: {}", url, start_index);

            let _ = fetch_entries(
                start_index,
                signed_tree_head.tree_size as usize,
                &url,
                tx,
                rate_limiter,
                &http_client,
                current_pos_reference,
                fetcher_count_reference,
            )
            .await;
        });

        Ok(())
    }

    async fn download_historic_dates(
        &self,
        tx: Sender<Bytes>,
        start_date: u64,
        end_date: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = self.url.clone();
        let http_client = self.http_client.clone();

        let start_reference = self.start.clone();
        let end_reference = self.end.clone();
        let current_pos_reference = self.current_pos.clone();
        let fetch_count_reference = self.fetch_count.clone();

        tokio::spawn(async move {
            let init_bytes = Bytes::new();

            // need to to use channel once, otherwise closes one parser
            let _ = tx.send(init_bytes).await;

            let rate_limiter = TokenBucketLimiter::new(10.0, 5.0);

            let signed_tree_head = match fetch_sth(&url, &http_client, &rate_limiter).await {
                Ok(sth) => sth,
                Err(_) => {
                    return;
                }
            };

            let (start_result, end_result) = tokio::join!(
                search_date(
                    &url,
                    &http_client,
                    &rate_limiter,
                    start_date,
                    &signed_tree_head,
                ),
                search_date(
                    &url,
                    &http_client,
                    &rate_limiter,
                    end_date,
                    &signed_tree_head,
                )
            );

            let start_index = match start_result {
                Ok(s_i) => s_i,
                Err(_) => {
                    return;
                }
            };

            let end_index = match end_result {
                Ok(e_i) => e_i,
                Err(_) => {
                    return;
                }
            };

            start_reference.store(start_index as u64, std::sync::atomic::Ordering::Relaxed);
            end_reference.store(end_index as u64, std::sync::atomic::Ordering::Relaxed);
            current_pos_reference.store(start_index as u64, std::sync::atomic::Ordering::Relaxed);

            let _ = fetch_entries(
                start_index,
                end_index,
                &url,
                tx,
                rate_limiter,
                &http_client,
                current_pos_reference,
                fetch_count_reference,
            )
            .await;
        });

        Ok(())
    }

    async fn download_historic_index(
        &self,
        tx: Sender<Bytes>,
        start_index: u64,
        end_index: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let url = self.url.clone();
        let http_client = self.http_client.clone();

        let start_reference = self.start.clone();
        let end_reference = self.end.clone();
        let current_pos_reference = self.current_pos.clone();
        let fetch_count_reference = self.fetch_count.clone();

        tokio::spawn(async move {
            let init_bytes = Bytes::new();

            // need to to use channel once, otherwise closes one parser
            let _ = tx.send(init_bytes).await;

            let rate_limiter = TokenBucketLimiter::new(10.0, 5.0);

            start_reference.store(start_index, std::sync::atomic::Ordering::Relaxed);
            end_reference.store(end_index, std::sync::atomic::Ordering::Relaxed);
            current_pos_reference.store(start_index, std::sync::atomic::Ordering::Relaxed);

            let _ = fetch_entries(
                start_index as usize,
                end_index as usize,
                &url,
                tx,
                rate_limiter,
                &http_client,
                current_pos_reference,
                fetch_count_reference,
            )
            .await;
        });

        Ok(())
    }

    fn search_timestamp(&self, datetime: u64) -> JoinHandle<()> {
        let url = self.url.clone();
        let http_client = self.http_client.clone();
        let handle = tokio::spawn(async move {
            let rate_limiter = TokenBucketLimiter::new(10.0, 5.0);
            let sth = match fetch_sth(&url, &http_client, &rate_limiter).await {
                Ok(sth) => sth,
                Err(e) => {
                    eprintln!("Error fetching STH for {}: {}", url, e);
                    return;
                }
            };

            let index = match search_date(&url, &http_client, &rate_limiter, datetime, &sth).await {
                Ok(idx) => idx,
                Err(e) => {
                    eprintln!("Error searching for date {} in {}: {:?}", datetime, url, e);
                    return;
                }
            };
            println!("Found index {} for date {} in log {}", index, datetime, url);
        });
        handle
    }

    fn monitor(&self, tx: Sender<Bytes>) -> anyhow::Result<()> {
        let url = self.url.clone();
        let http_client = self.http_client.clone();

        let start_reference = self.start.clone();
        let end_reference = self.end.clone();
        let current_pos_reference = self.current_pos.clone();
        let fetch_count_reference = self.fetch_count.clone();

        tokio::spawn(async move {
            let mut current_index = None;

            let rate_limiter = TokenBucketLimiter::new(10.0, 5.0);

            let wait_time = Duration::from_secs(60);
            loop {
                let sth = match fetch_sth(&url, &http_client, &rate_limiter).await {
                    Ok(sth) => sth,
                    Err(e) => {
                        eprintln!("Error fetching STH for {}: {}", url, e);
                        tokio::time::sleep(wait_time).await;
                        continue;
                    }
                };

                println!(
                    "Log: {}, Tree size: {}, Timestamp: {}",
                    url, sth.tree_size, sth.timestamp
                );

                let tree_size = sth.tree_size;

                let Some(index) = current_index else {
                    current_index = Some(tree_size as usize);

                    start_reference.store(tree_size, std::sync::atomic::Ordering::Relaxed);

                    end_reference.store(tree_size, std::sync::atomic::Ordering::Relaxed);

                    current_pos_reference.store(tree_size, std::sync::atomic::Ordering::Relaxed);

                    tokio::time::sleep(wait_time).await;
                    continue;
                };

                if index >= tree_size as usize {
                    println!(
                        "No new entries in log {}. Current index: {}, Tree size: {}",
                        url, index, tree_size
                    );
                    tokio::time::sleep(wait_time).await;
                    continue;
                }

                current_pos_reference.store(index as u64, std::sync::atomic::Ordering::Relaxed);
                end_reference.store(tree_size, std::sync::atomic::Ordering::Relaxed);
                // TODO: fetch entries should return a result
                let _ = fetch_entries(
                    index,
                    tree_size as usize,
                    &url,
                    tx.clone(),
                    rate_limiter.clone(),
                    &http_client,
                    current_pos_reference.clone(),
                    fetch_count_reference.clone(),
                )
                .await;

                current_index = Some(tree_size as usize);

                tokio::time::sleep(wait_time).await;
            }
        });
        Ok(())
    }
}

#[derive(Debug)]
enum FetchError {
    RateLimited,
    Other(anyhow::Error),
}

impl<E: Into<anyhow::Error>> From<E> for FetchError {
    fn from(e: E) -> Self {
        FetchError::Other(e.into())
    }
}

pub struct Fetcher {
    logs: Vec<CTLog>,
    http_client: reqwest::Client,
}

// TODO: maybe add state tracking
impl Fetcher {
    pub async fn create_gstatic(
        start_date: DateTime<Utc>,
        end_date: DateTime<Utc>,
    ) -> anyhow::Result<Self> {
        let mut ct_logs: Vec<CTLog> = Vec::new();

        // let http_client = reqwest::Client::builder()
        //     .pool_idle_timeout(Duration::from_secs(10))
        //     .timeout(Duration::from_secs(5))
        //     .build()
        //     .unwrap();

        let http_client = reqwest::Client::new();

        let log_urls = fetch_gstatic_logs(start_date, end_date).await?;

        for url in log_urls {
            let ct_log = CTLog::new(url, http_client.clone());
            ct_logs.push(ct_log);
        }

        Ok(Self {
            logs: ct_logs,
            http_client,
        })
    }

    // does not need to be async, but kept for consistency and could be async with tokio but why?
    pub async fn create_from_file(file_path: &str) -> anyhow::Result<Self> {
        let mut ct_logs: Vec<CTLog> = Vec::new();

        let http_client = reqwest::Client::new();

        let log_urls = std::fs::read_to_string(file_path)?;

        for url in log_urls.lines() {
            let ct_log = CTLog::new(url.to_string(), http_client.clone());
            ct_logs.push(ct_log);
        }

        Ok(Self {
            logs: ct_logs,
            http_client,
        })
    }

    pub async fn start_to_sth(&self, start_date: u64) -> anyhow::Result<mpsc::Receiver<Bytes>> {
        let (tx, rx) = mpsc::channel::<Bytes>(1000);

        for log in &self.logs {
            let log_tx = tx.clone();
            let _ = log.download_to_tree_size(log_tx, start_date).await;
        }

        drop(tx);
        Ok(rx)
    }

    pub async fn start_historic(
        &self,
        start_date: u64,
        end_date: u64,
    ) -> anyhow::Result<mpsc::Receiver<Bytes>> {
        let (tx, rx) = mpsc::channel::<Bytes>(1000);

        for log in &self.logs {
            let log_tx = tx.clone();
            let _ = log
                .download_historic_dates(log_tx, start_date, end_date)
                .await;
        }

        drop(tx);
        Ok(rx)
    }

    pub async fn start_monitor(&self) -> anyhow::Result<mpsc::Receiver<Bytes>> {
        let (tx, rx) = mpsc::channel::<Bytes>(1000);

        for log in &self.logs {
            let log_tx = tx.clone();
            let _ = log.monitor(log_tx);
        }

        drop(tx);
        Ok(rx)
    }

    pub async fn create_from_url(url: &str) -> anyhow::Result<Self> {
        let mut ct_logs: Vec<CTLog> = Vec::new();

        let http_client = reqwest::Client::new();

        let ct_log = CTLog::new(url.to_string(), http_client.clone());
        ct_logs.push(ct_log);

        Ok(Self {
            logs: ct_logs,
            http_client,
        })
    }

    pub async fn spawn_reporter(&self) -> anyhow::Result<()> {
        let mut log_states = Vec::new();
        for log in &self.logs {
            let log_state_entry = CTLogState {
                url: log.url.clone(),
                start: log.start.clone(),
                end: log.end.clone(),
                current_pos: log.current_pos.clone(),
                fetch_count: log.fetch_count.clone(),

                start_plain: 0,
                end_plain: 0,
            };
            log_states.push(log_state_entry);
        }

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;

                for log_state in &mut log_states {
                    let current_pos = log_state
                        .current_pos
                        .load(std::sync::atomic::Ordering::Relaxed);

                    if log_state.start_plain == 0 {
                        log_state.start_plain =
                            log_state.start.load(std::sync::atomic::Ordering::Relaxed);
                    }

                    if log_state.end_plain == 0 {
                        log_state.end_plain =
                            log_state.end.load(std::sync::atomic::Ordering::Relaxed);
                    }

                    let progress_percentage = current_pos.saturating_sub(log_state.start_plain)
                        as f64
                        / log_state.end_plain.saturating_sub(log_state.start_plain) as f64
                        * 100.0;

                    let current_fetch_rate = log_state
                        .fetch_count
                        .load(std::sync::atomic::Ordering::Relaxed)
                        as f64
                        / 60.0;

                    log_state
                        .fetch_count
                        .store(0, std::sync::atomic::Ordering::Relaxed);

                    println!(
                        "Log: {}, Progress: ({:.2}%) current {} start: {} end: {}, Current fetch rate: {:.2} entries/sec",
                        log_state.url,
                        progress_percentage,
                        current_pos,
                        log_state.start_plain,
                        log_state.end_plain,
                        current_fetch_rate
                    );
                }
            }
        });
        Ok(())
    }

    pub async fn start_timestamp_search(&self, timestamp: u64) -> anyhow::Result<()> {
        let mut handles = Vec::new();

        for log in &self.logs {
            let handle = log.search_timestamp(timestamp);
            handles.push(handle);
        }

        for handle in handles {
            handle.await?;
        }

        Ok(())
    }

    pub async fn start_index_range(
        &self,
        start_index: u64,
        end_index: u64,
    ) -> anyhow::Result<mpsc::Receiver<Bytes>> {
        let (tx, rx) = mpsc::channel::<Bytes>(1000);

        for log in &self.logs {
            let log_tx = tx.clone();
            let _ = log
                .download_historic_index(log_tx, start_index, end_index)
                .await;
        }

        drop(tx);
        Ok(rx)
    }
}

async fn fetch_entries(
    start_index: usize,
    end_index: usize,
    url: &str,
    tx: Sender<Bytes>,
    rate_limiter: TokenBucketLimiter,
    http_client: &reqwest::Client,
    current_pos_reference: Arc<AtomicU64>,
    fetch_count_reference: Arc<AtomicU64>,
) {
    // println!(
    //     "Fetching entries from {} to {} for {}",
    //     start_index, end_index, url
    // );
    let batch_size = 1024;
    let error_sleep_time = Duration::from_secs(1);

    let mut current_index = start_index;

    let concurrent_range_fetches = 10;
    let semaphore = Arc::new(Semaphore::new(concurrent_range_fetches));

    while current_index < end_index as usize {
        // println!(
        //     "Fetching loop entries from {} to {} for {}",
        //     current_index,
        //     (current_index + batch_size).min(end_index as usize),
        //     url
        // );
        let permit = semaphore.clone().acquire_owned().await.unwrap();

        let url = url.to_string();
        let http_client = http_client.clone();
        let rate_limiter = rate_limiter.clone();
        let tx = tx.clone();
        let fetch_count_reference = fetch_count_reference.clone();

        let mut current_sub_range_start = current_index;
        let sub_range_end = (current_index + batch_size).min(end_index as usize);

        current_index = sub_range_end;

        tokio::spawn(async move {
            while current_sub_range_start < sub_range_end {
                rate_limiter.wait().await;

                let batch =
                    match fetch_batch(&url, &http_client, current_sub_range_start, sub_range_end)
                        .await
                    {
                        Ok(b) => {
                            rate_limiter.increase().await;
                            b
                        }
                        Err(FetchError::RateLimited) => {
                            rate_limiter.backoff().await;
                            sleep(error_sleep_time).await;
                            continue;
                        }
                        Err(FetchError::Other(e)) => {
                            eprintln!(
                                "Fetch failed for range :{}, error: {:?}",
                                current_sub_range_start, e
                            );

                            rate_limiter.backoff().await;
                            sleep(error_sleep_time).await;
                            continue;
                        }
                    };

                current_sub_range_start += batch.len();
                let current_rate = rate_limiter.get_refill_rate().await;
                // println!(
                //     "Fetched {} entries from {} to {} for {}, current_sub_range_start: {}, current refill rate: {}",
                //     batch.len(),
                //     current_sub_range_start - batch.len(),
                //     current_sub_range_start,
                //     url,
                //     current_sub_range_start,
                //     current_rate
                // );
                fetch_count_reference.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                for entry in batch {
                    let _ = tx.send(entry).await;
                }
            }

            drop(permit);
        });
        current_pos_reference.fetch_max(current_index as u64, std::sync::atomic::Ordering::Relaxed);
    }
    drop(tx);
}

pub async fn fetch_gstatic_logs(
    start_date: DateTime<Utc>,
    end_date: DateTime<Utc>,
) -> anyhow::Result<Vec<String>> {
    let mut log_urls: Vec<String> = Vec::new();
    let max_retries = 3;
    let url = "https://www.gstatic.com/ct/log_list/v3/log_list.json";
    let mut log_list: Option<LogList> = None;
    println!("Fetching the log provider from {}", url);

    for attempt in 0..max_retries {
        match reqwest::get(url).await {
            Ok(response) => match response.json::<LogList>().await {
                Ok(parsed_json) => {
                    log_list = Some(parsed_json);
                    break;
                }
                Err(e) => {
                    eprint!("Failed to parse json! {}", e);
                }
            },
            Err(e) => {
                eprintln!("Failed to fetch {}, {}", url, e);
            }
        }
        if attempt < max_retries - 1 {
            sleep(Duration::from_secs(2u64.pow(attempt))).await;
        }
    }
    let log_list = log_list.context("Failed to fetch or parse CT Log collection!")?;

    for operator in log_list.operators {
        for log in operator.logs {
            let log_start_date =
                DateTime::parse_from_rfc3339(&log.temporal_interval.start_inclusive)?
                    .with_timezone(&Utc);
            let log_end_date = DateTime::parse_from_rfc3339(&log.temporal_interval.end_exclusive)?
                .with_timezone(&Utc);

            if log_start_date <= end_date && log_end_date >= start_date {
                println!(
                    "log url: {}, dates: {}, {}",
                    log.url, log_start_date, start_date
                );
                log_urls.push(log.url);
            }
        }
    }
    Ok(log_urls)
}

async fn search_date(
    url: &str,
    http_client: &reqwest::Client,
    rate_limiter: &TokenBucketLimiter,
    date: u64,
    sth: &Sth,
) -> Result<usize, FetchError> {
    let mut low = 0;
    let mut high = 0;
    let sth_offset = 10;

    if sth.tree_size > sth_offset {
        high = sth.tree_size - sth_offset;
    }

    if date > sth.timestamp {
        return Ok(high as usize);
    }

    let mut first_time = None;
    let max_retries = 5;

    for _ in 0..max_retries {
        rate_limiter.wait().await;

        match fetch_entry_timestamp(url, http_client, 0).await {
            Ok(Some(ts)) => {
                first_time = Some(ts);
                break;
            }
            Ok(None) => break,
            Err(FetchError::RateLimited) => {
                eprintln!("rate limited {}", url);
                rate_limiter.backoff().await;
                sleep(Duration::from_secs(2)).await;
            }
            Err(e) => return Err(e),
        }
    }

    if let Some(first_time) = first_time {
        if date <= first_time {
            dbg!(date, first_time);
            return Ok(0);
        }
    }

    while low <= high {
        let mut timestamp = None;
        let mut retries = 0;

        let mid = low + (high - low) / 2;

        while retries < max_retries {
            rate_limiter.wait().await;

            match fetch_entry_timestamp(url, http_client, mid as usize).await {
                Ok(Some(ts)) => {
                    timestamp = Some(ts);
                    break;
                }
                Ok(None) => {
                    retries += 1;

                    eprintln!("Log returned empty entry at index {}, {}", mid, url);

                    sleep(Duration::from_secs(1 * retries as u64)).await;
                }
                Err(FetchError::RateLimited) => {
                    retries += 1;

                    eprintln!(
                        "Rate limited at {}, attempt {}/{}, {}",
                        mid, retries, max_retries, url
                    );

                    rate_limiter.backoff().await;

                    sleep(Duration::from_secs(1 * retries as u64)).await;
                }
                Err(e) => {
                    retries += 1;

                    eprintln!("Network error at index {}, {}", mid, url);

                    sleep(Duration::from_secs(1 * retries as u64)).await;
                }
            }
        }

        let timestamp = match timestamp {
            Some(ts) => ts,
            None => return Err(FetchError::RateLimited),
        };

        // let timestamp = fetch_entry_timestamp(url, http_client, mid as usize)
        //     .await?
        //     .unwrap();

        if timestamp < date {
            low = mid + 1;
        } else {
            high = mid - 1;
        }
    }

    Ok(low as usize)
}

async fn fetch_entry_timestamp(
    url: &str,
    http_client: &reqwest::Client,
    index: usize,
) -> Result<Option<u64>, FetchError> {
    let start = Instant::now();
    let batch = fetch_batch(url, http_client, index, index).await?;
    // add retrys
    println!("Timestamp fetch {}, {}", url, start.elapsed().as_secs_f64());

    if let Some(entry) = batch.first() {
        let timestamp = parser::parse_timestamp(entry.clone());
        return Ok(timestamp);
    }

    Ok(None)
}

async fn fetch_sth(
    url: &str,
    http_client: &reqwest::Client,
    rate_limiter: &TokenBucketLimiter,
) -> anyhow::Result<Sth> {
    let sth_url = format!("{}ct/v1/get-sth", url);

    let max_retry = 10;
    let retry_secs: u64 = 3;

    for retry in 0..max_retry {
        rate_limiter.wait().await;
        let response = match http_client.get(&sth_url).send().await {
            Ok(res) => res,
            Err(_) => {
                eprintln!("Failed to fetch the sth for {}, attempt: {}", url, retry);
                rate_limiter.backoff().await;
                sleep(Duration::from_secs(retry_secs.pow(retry))).await;
                continue;
            }
        };

        rate_limiter.increase().await;

        match response.json::<Sth>().await {
            Ok(res) => {
                return Ok(res);
            }
            Err(_) => {
                eprintln!("Failed to parse the sth for {}, attempt: {}", url, retry);
                sleep(Duration::from_secs(retry_secs.pow(retry))).await;
                continue;
            }
        };
    }

    Err(anyhow!("Failed to fetch STH after retries"))
}

async fn fetch_batch(
    entries_url: &str,
    http_client: &reqwest::Client,
    start: usize,
    end: usize,
) -> Result<Vec<Bytes>, FetchError> {
    let start_end_url = format!(
        "{}ct/v1/get-entries?start={}&end={}",
        entries_url, start, end
    );

    let response = http_client.get(start_end_url).send().await?;

    let status = response.status();

    if status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::INTERNAL_SERVER_ERROR {
        return Err(FetchError::RateLimited);
    }

    if !status.is_success() {
        return Err(FetchError::Other(anyhow::anyhow!(
            "something broke: {}",
            status
        )));
    }

    let response_bytes = response.bytes().await?;

    let batch: Entries = serde_json::from_slice(&response_bytes)?;

    let mut decoded_entries = Vec::with_capacity(batch.entries.len());

    for entry in batch.entries {
        if let Ok(decoded_vec) = STANDARD.decode(entry.leaf_input) {
            decoded_entries.push(Bytes::from(decoded_vec));
        }
    }
    Ok(decoded_entries)
}
