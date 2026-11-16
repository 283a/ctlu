use sqlx::postgres::PgPoolOptions;
use tokio::{
    fs::File,
    io::{AsyncWriteExt, BufWriter},
};

use crate::crawler::parser;

pub async fn output_txt(mut parser_rx: tokio::sync::mpsc::Receiver<String>) {
    let file = match File::options()
        .create(true)
        .append(true)
        .open("data/domains.txt")
        .await
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Failed to open domains.txt: {e}");
            return;
        }
    };

    let mut writer = BufWriter::new(file);

    while let Some(domain) = parser_rx.recv().await {
        if let Err(e) = writer.write_all(format!("{}\n", domain).as_bytes()).await {
            eprintln!("Failed to write domain to buffer: {e}");
            break;
        }
        let _ = writer.flush().await;
    }

    if let Err(e) = writer.flush().await {
        eprintln!("Failed to flush final domains to disk: {e}");
    }
}

pub async fn output_sqlite(
    mut parser_rx: tokio::sync::mpsc::Receiver<parser::ParseResultDomainTimestamp>,
) -> anyhow::Result<()> {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename("data/domains.db")
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

    let db = match sqlx::SqlitePool::connect_with(options).await {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("Failed to connect to sqlite database: {e}");
            return Err(e.into());
        }
    };

    let create_table = "
    CREATE TABLE IF NOT EXISTS domains (
        domain TEXT PRIMARY KEY,
        seen_count INTEGER NOT NULL DEFAULT 1,
        first_seen INTEGER NOT NULL,
        last_seen INTEGER NOT NULL
    );";

    if let Err(e) = sqlx::query(create_table).execute(&db).await {
        eprintln!("Failed to create table: {e}");
        return Err(e.into());
    }

    let mut buffer = Vec::new();

    while parser_rx.recv_many(&mut buffer, 1000).await > 0 {
        let mut tx = match db.begin().await {
            Ok(tx) => tx,
            Err(e) => {
                eprintln!("Failed to start transaction: {e}");
                buffer.clear();
                continue;
            }
        };

        for item in buffer.drain(..) {
            let ts = item.timestamp as i64;

            for domain in item.domains {
                let query = "
                INSERT INTO domains (domain, seen_count, first_seen, last_seen)
                VALUES (?, 1, ?, ?)
                ON CONFLICT(domain) DO UPDATE SET
                seen_count = seen_count + 1,
                last_seen = excluded.last_seen;
                ";

                if let Err(e) = sqlx::query(query)
                    .bind(&domain)
                    .bind(ts)
                    .bind(ts)
                    .execute(&mut *tx)
                    .await
                {
                    eprintln!("Failed to insert domain '{domain}': {e}");
                }
            }
        }

        if let Err(e) = tx.commit().await {
            eprintln!("Failed to commit transaction batch: {e}");
        }
    }

    db.close().await;
    Ok(())
}

// pub async fn output_postgres_cert(
//     mut parser_rx: tokio::sync::mpsc::Receiver<parser::ParseResult>,
// ) -> anyhow::Result<()> {
    // let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    // let db = PgPoolOptions::new()
    //     .max_connections(5)
    //     .connect(&database_url)
    //     .await?;

    // sqlx::query(
    //     r#"
    //     CREATE TABLE IF NOT EXISTS domains (
    //         domain TEXT PRIMARY KEY,
    //         seen_count BIGINT NOT NULL DEFAULT 1,
    //         first_seen BIGINT NOT NULL,
    //         last_seen BIGINT NOT NULL
    //     )
    //     "#,
    // )
    // .execute(&db)
    // .await?;

    // let mut buffer = Vec::with_capacity(1000);

    // while parser_rx.recv_many(&mut buffer, 1000).await > 0 {
    //     let mut tx = match db.begin().await {
    //         Ok(tx) => tx,
    //         Err(e) => {
    //             eprintln!("Failed to start transaction: {e}");
    //             buffer.clear();
    //             continue;
    //         }
    //     };

    //     for item in buffer.drain(..) {
    //         let ts = item.timestamp as i64;

    //         for domain in item.domains {
    //             let query = r#"
    //                 INSERT INTO domains (
    //                     domain,
    //                     seen_count,
    //                     first_seen,
    //                     last_seen
    //                 )
    //                 VALUES ($1, 1, $2, $3)
    //                 ON CONFLICT (domain) DO UPDATE SET
    //                     seen_count = domains.seen_count + 1,
    //                     last_seen = EXCLUDED.last_seen
    //             "#;

    //             if let Err(e) = sqlx::query(query)
    //                 .bind(&domain)
    //                 .bind(ts)
    //                 .bind(ts)
    //                 .execute(&mut *tx)
    //                 .await
    //             {
    //                 eprintln!("Failed to insert domain '{domain}': {e}");
    //             }
    //         }
    //     }

    //     if let Err(e) = tx.commit().await {
    //         eprintln!("Failed to commit transaction batch: {e}");
    //     }
    // }

    // db.close().await;

    // Ok(())
// }
