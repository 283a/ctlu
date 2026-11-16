use futures::TryStreamExt;
use sqlx::AssertSqlSafe;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::sync::mpsc::Receiver;
use tokio::time::Instant;

mod dns_engine;

#[derive(Debug)]
pub struct ResolvedResult {
    pub domain: String,
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
}

#[derive(sqlx::FromRow)]
struct DomainRow {
    domain: String,
}

pub async fn fetch_domains_db(
    db: sqlx::SqlitePool,
) -> anyhow::Result<tokio::sync::mpsc::Receiver<String>> {
    let (db_fetcher_tx, db_fetcher_rx) = tokio::sync::mpsc::channel::<String>(1000);

    tokio::spawn(async move {
        let result: anyhow::Result<()> = async {
            let mut rows = sqlx::query_as::<_, DomainRow>("SELECT domain FROM domains").fetch(&db);

            while let Some(row) = rows.try_next().await? {
                if db_fetcher_tx.send(row.domain).await.is_err() {
                    break;
                }
            }

            Ok(())
        }
        .await;

        if let Err(err) = result {
            eprintln!("Error fetching domains from DB: {err}");
            return;
        }
    });

    Ok(db_fetcher_rx)
}

pub async fn resolve_domains(
    mut db_fetcher_rx: Receiver<String>,
) -> anyhow::Result<Receiver<ResolvedResult>> {
    let (resolver_tx, resolver_rx) = tokio::sync::mpsc::channel::<ResolvedResult>(1000);

    let dns_engine = Arc::new(dns_engine::DnsEnginePool::new().await?);

    let semaphore = Arc::new(Semaphore::new(2000));

    tokio::spawn(async move {
        while let Some(domain) = db_fetcher_rx.recv().await {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let resolver_tx_clone = resolver_tx.clone();
            let dns_engine_clone = dns_engine.clone();

            tokio::spawn(async move {
                let _permit = permit;

                let result = dns_engine_clone.lookup_v4_v6(&domain).await;

                match result {
                    Ok(lookup_result) => {
                        let resolved_result = ResolvedResult {
                            domain: domain.clone(),
                            ipv4: lookup_result.v4,
                            ipv6: lookup_result.v6,
                        };

                        if resolver_tx_clone.send(resolved_result).await.is_err() {
                            eprintln!("Failed to send resolved result for domain: {}", domain);
                        }
                    }
                    Err(_err) => {
                        // eprintln!("DNS resolution failed for domain {}: {}", domain, err);
                    }
                }
            });
        }
    });

    Ok(resolver_rx)
}

pub async fn write_resolved_results(
    db: sqlx::SqlitePool,
    mut resolver_rx: tokio::sync::mpsc::Receiver<ResolvedResult>,
) -> anyhow::Result<()> {
    let table_name = format!(
        "resolved_domains_{}",
        chrono::Utc::now().format("%Y_%m_%d_%H_%M_%S")
    );

    let create_table_query = format!(
        "CREATE TABLE IF NOT EXISTS {} (
            domain TEXT NOT NULL,
            record_type TEXT,
            ip TEXT,
            resolved_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        );",
        table_name
    );

    if let Err(err) = sqlx::query(AssertSqlSafe(create_table_query.as_str()))
        .execute(&db)
        .await
    {
        eprintln!("Failed to create table {}: {}", table_name, err);
        return Err(err.into());
    }

    let insert_query = format!(
        r#"
            INSERT INTO "{}" (domain, record_type, ip)
            VALUES (?, ?, ?)
            "#,
        table_name
    );

    let mut buffer = Vec::new();

    let mut count = 0u64;
    let mut last_print = Instant::now();

    while resolver_rx.recv_many(&mut buffer, 500).await > 0 {
        let mut tx = match db.begin().await {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("Failed to begin transaction: {e}");
                continue;
            }
        };

        for resolved_result in buffer.drain(..) {
            if resolved_result.ipv4.is_empty() {
                if let Err(err) = sqlx::query(AssertSqlSafe(insert_query.as_str()))
                    .bind(&resolved_result.domain)
                    .bind("A")
                    .bind(Option::<String>::None)
                    .execute(&mut *tx)
                    .await
                {
                    eprintln!(
                        "Failed to insert resolved result for domain {}: {}",
                        resolved_result.domain, err
                    );
                };
            } else {
                for ipv4 in resolved_result.ipv4 {
                    if let Err(err) = sqlx::query(AssertSqlSafe(insert_query.as_str()))
                        .bind(&resolved_result.domain)
                        .bind("A")
                        .bind(ipv4.to_string())
                        .execute(&mut *tx)
                        .await
                    {
                        eprintln!(
                            "Failed to insert resolved result for domain {}: {}",
                            resolved_result.domain, err
                        );
                    };
                }
            }

            if resolved_result.ipv6.is_empty() {
                if let Err(err) = sqlx::query(AssertSqlSafe(insert_query.as_str()))
                    .bind(&resolved_result.domain)
                    .bind("AAAA")
                    .bind(Option::<String>::None)
                    .execute(&mut *tx)
                    .await
                {
                    eprintln!(
                        "Failed to insert resolved result for domain {}: {}",
                        resolved_result.domain, err
                    );
                };
            } else {
                for ipv6 in resolved_result.ipv6 {
                    if let Err(err) = sqlx::query(AssertSqlSafe(insert_query.as_str()))
                        .bind(&resolved_result.domain)
                        .bind("AAAA")
                        .bind(ipv6.to_string())
                        .execute(&mut *tx)
                        .await
                    {
                        eprintln!(
                            "Failed to insert resolved result for domain {}: {}",
                            resolved_result.domain, err
                        );
                    };
                }
            }
        }

        if let Err(err) = tx.commit().await {
            eprintln!("Failed to commit transaction: {}", err);
        }

        count += 1;

        if last_print.elapsed() > Duration::from_secs(60) {
            println!("Dns results processed {}", count);
            last_print = Instant::now();
        }
    }
    Ok(())
}

pub async fn resolve_domains_sqlite(path: String) -> anyhow::Result<()> {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename("data/domains.db")
        // .filename(path)
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

    let db = sqlx::SqlitePool::connect_with(options).await?;

    let db_fetcher_rx = fetch_domains_db(db.clone()).await?;

    let resolver_rx = resolve_domains(db_fetcher_rx).await?;

    let _ = tokio::select! {
        result = write_resolved_results(db.clone(), resolver_rx)=> {
            result?;
        }

        _ = tokio::signal::ctrl_c() => {
            println!("Ctrl+C received, shutting down...");
            db.close().await;
            return Ok(());
        }
    };

    db.close().await;

    println!("DNS resolution completed and results written to the database.");

    // let _ = write_resolved_results(db.clone(), resolver_rx).await?;

    Ok(())
}
