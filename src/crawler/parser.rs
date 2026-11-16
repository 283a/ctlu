use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use tokio::sync::mpsc;
use x509_parser::{asn1_rs::UtcTime, prelude::*};

struct Parser;

pub enum ParseResult {
    ParseResultDomainTimestamp(ParseResultDomainTimestamp),
    ParseResultCert(ParseResultCert),
}

pub(crate) struct ParseResultDomainTimestamp {
    pub domains: Vec<String>,
    pub timestamp: u64,
}

// TODO: change to traits based on mode selection
pub async fn spawn(
    mut fetcher_rx: tokio::sync::mpsc::Receiver<Bytes>,
) -> anyhow::Result<mpsc::Receiver<String>> {
    let (tx, rx) = mpsc::channel::<String>(1000);

    let tx_c = tx.clone();

    tokio::spawn(async move {
        while let Some(leaf_cert_bytes) = fetcher_rx.recv().await {
            let domains = parse_leaf_cert(leaf_cert_bytes);
            if let Some(domains) = domains {
                for domain in domains {
                    let _ = tx_c.send(domain).await;
                }
            }
        }
    });

    drop(tx);
    Ok(rx)
}

pub async fn spawn_domain(
    mut fetcher_rx: tokio::sync::mpsc::Receiver<Bytes>,
) -> anyhow::Result<mpsc::Receiver<ParseResultDomainTimestamp>> {
    let (tx, rx) = mpsc::channel::<ParseResultDomainTimestamp>(1000);

    let tx_c = tx.clone();

    tokio::spawn(async move {
        while let Some(leaf_cert_bytes) = fetcher_rx.recv().await {
            let parse_result = parse_leaf_cert_domains_timestamp(leaf_cert_bytes);
            if let Some(parse_result) = parse_result {
                let _ = tx_c.send(parse_result).await;
            }
        }
    });

    drop(tx);
    Ok(rx)
}

pub async fn spawn_cert(
    mut fetcher_rx: tokio::sync::mpsc::Receiver<Bytes>,
) -> anyhow::Result<mpsc::Receiver<ParseResult>> {
    let (tx, rx) = mpsc::channel::<ParseResult>(1000);

    let tx_c = tx.clone();

    tokio::spawn(async move {
        while let Some(leaf_cert_bytes) = fetcher_rx.recv().await {
            let parse_result = parse_leaf_cert_data(leaf_cert_bytes);
            if let Some(parse_result) = parse_result {
                let _ = tx_c.send(ParseResult::ParseResultCert(parse_result)).await;
            }
        }
    });

    drop(tx);
    Ok(rx)
}

// TODO: parse cert send cert save cert to db
// have a cert returner

pub fn parse_leaf_cert(decoded_leaf_cert: Bytes) -> Option<Vec<String>> {
    if decoded_leaf_cert.len() < 15 {
        return None;
    }

    let mut domains: Vec<String> = Vec::new();

    let _version = decoded_leaf_cert[0];
    let _leaf_type = decoded_leaf_cert[1];
    let _timestamp = u64::from_be_bytes(decoded_leaf_cert[2..10].try_into().ok()?);
    let log_entry_type = u16::from_be_bytes([decoded_leaf_cert[10], decoded_leaf_cert[11]]);

    // precerts are put into log after MMD
    if log_entry_type != 0 {
        return None;
    }

    let cert_len = u32::from_be_bytes([
        0,
        decoded_leaf_cert[12],
        decoded_leaf_cert[13],
        decoded_leaf_cert[14],
    ]) as usize;

    if decoded_leaf_cert.len() < 15 + cert_len {
        return None;
    }

    let (_rem, x509_parsed) =
        X509Certificate::from_der(&decoded_leaf_cert[15..15 + cert_len]).ok()?;

    if let Ok(Some(san)) = x509_parsed.subject_alternative_name() {
        for general_name in &san.value.general_names {
            if let GeneralName::DNSName(dns_name) = general_name {
                domains.push(dns_name.to_ascii_lowercase());
            }
        }
    }

    if domains.is_empty() {
        for common_name in x509_parsed.subject().iter_common_name() {
            if let Ok(name) = common_name.as_str() {
                domains.push(name.to_ascii_lowercase());
            }
        }
    }

    Some(domains)
}

pub fn parse_leaf_cert_domains_timestamp(
    decoded_leaf_cert: Bytes,
) -> Option<ParseResultDomainTimestamp> {
    if decoded_leaf_cert.len() < 15 {
        return None;
    }

    let mut domains: Vec<String> = Vec::new();

    let _version = decoded_leaf_cert[0];
    let _leaf_type = decoded_leaf_cert[1];
    let timestamp = u64::from_be_bytes(decoded_leaf_cert[2..10].try_into().ok()?);
    let log_entry_type = u16::from_be_bytes([decoded_leaf_cert[10], decoded_leaf_cert[11]]);

    // precerts are put into log after MMD
    if log_entry_type != 0 {
        return None;
    }

    let cert_len = u32::from_be_bytes([
        0,
        decoded_leaf_cert[12],
        decoded_leaf_cert[13],
        decoded_leaf_cert[14],
    ]) as usize;

    if decoded_leaf_cert.len() < 15 + cert_len {
        return None;
    }

    let (_rem, x509_parsed) =
        X509Certificate::from_der(&decoded_leaf_cert[15..15 + cert_len]).ok()?;

    if let Ok(Some(san)) = x509_parsed.subject_alternative_name() {
        for general_name in &san.value.general_names {
            if let GeneralName::DNSName(dns_name) = general_name {
                domains.push(dns_name.to_ascii_lowercase());
            }
        }
    }

    if domains.is_empty() {
        for common_name in x509_parsed.subject().iter_common_name() {
            if let Ok(name) = common_name.as_str() {
                domains.push(name.to_ascii_lowercase());
            }
        }
    }

    Some(ParseResultDomainTimestamp { domains, timestamp })
}

pub struct ParseResultCert {
    pub pki: String,
    pub timestamp: u64,
    pub domains: Vec<String>,
}

pub fn parse_leaf_cert_data(decoded_leaf_cert: Bytes) -> Option<ParseResultCert> {
    if decoded_leaf_cert.len() < 15 {
        return None;
    }

    let mut domains: Vec<String> = Vec::new();

    let _version = decoded_leaf_cert[0];
    let _leaf_type = decoded_leaf_cert[1];
    let timestamp = u64::from_be_bytes(decoded_leaf_cert[2..10].try_into().ok()?);
    let log_entry_type = u16::from_be_bytes([decoded_leaf_cert[10], decoded_leaf_cert[11]]);

    // precerts are put into log after MMD
    if log_entry_type != 0 {
        return None;
    }

    let cert_len = u32::from_be_bytes([
        0,
        decoded_leaf_cert[12],
        decoded_leaf_cert[13],
        decoded_leaf_cert[14],
    ]) as usize;

    if decoded_leaf_cert.len() < 15 + cert_len {
        return None;
    }

    let (_rem, x509_parsed) =
        X509Certificate::from_der(&decoded_leaf_cert[15..15 + cert_len]).ok()?;

    let public_key = x509_parsed.public_key().raw;

    let pki_sha_256 = sha256::digest(public_key);

    if let Ok(Some(san)) = x509_parsed.subject_alternative_name() {
        for general_name in &san.value.general_names {
            if let GeneralName::DNSName(dns_name) = general_name {
                domains.push(dns_name.to_ascii_lowercase());
            }
        }
    }

    if domains.is_empty() {
        for common_name in x509_parsed.subject().iter_common_name() {
            if let Ok(name) = common_name.as_str() {
                domains.push(name.to_ascii_lowercase());
            }
        }
    }

    Some(ParseResultCert {
        pki: pki_sha_256,
        timestamp,
        domains,
    })
}

pub fn parse_timestamp(decoded_leaf_cert: Bytes) -> Option<u64> {
    if decoded_leaf_cert.len() < 15 {
        return None;
    }

    let _version = decoded_leaf_cert[0];
    let _leaf_type = decoded_leaf_cert[1];
    let timestamp = u64::from_be_bytes(decoded_leaf_cert[2..10].try_into().ok()?);

    Some(timestamp)
}

fn legacy_get_domains(leaf_input: String) -> anyhow::Result<Vec<String>> {
    let mut domains: Vec<String> = Vec::new();

    let decoded = STANDARD.decode(leaf_input)?;
    // v1:
    // struct {
    //        Version version;
    //        MerkleLeafType leaf_type;
    //        select (leaf_type) {
    //            case timestamped_entry: TimestampedEntry;
    //        }
    //    } MerkleTreeLeaf;
    //
    // in v1 only possiblewith the ct/v1/get-sth
    // version 1 byte(can only be 0 in v1)
    // leaf_type 1 byte(can only be 0 in v1) timpestampentry
    //
    // either ASN.1Cert
    // or PreCert
    // on log_entry_type 0 it is ASN.1Cert
    // on 1 preCert igonre precert precert are added anyway
    // rest of is cert chain

    let _version = &decoded[0];
    let _leaf_type = &decoded[1];
    let _timestamp = u64::from_be_bytes(decoded[2..10].try_into()?);
    let log_entry_type = u16::from_be_bytes([decoded[10], decoded[11]]);
    println!("{}", &log_entry_type);
    // precerts are put into log after MMD
    if log_entry_type != 0 {
        return Ok(domains);
    }

    let cert_len = u32::from_be_bytes([0, decoded[12], decoded[13], decoded[14]]) as usize;

    let (_rem, x509_parsed) = X509Certificate::from_der(&decoded[15..15 + cert_len])?;

    if let Ok(Some(san)) = x509_parsed.subject_alternative_name() {
        for general_name in &san.value.general_names {
            if let GeneralName::DNSName(dns_name) = general_name {
                domains.push(dns_name.to_ascii_lowercase());
            }
        }
    }

    if domains.is_empty() {
        for common_name in x509_parsed.subject().iter_common_name() {
            if let Ok(name) = common_name.as_str() {
                domains.push(name.to_ascii_lowercase());
            }
        }
    }
    Ok(domains)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_leaf_cert() {
        let entry = "AAAAAAGeGUGkZQABSbUYe80N5PUD3jhsoas+Cerx4jAWMp/rKd6dCI+gu5oABfAwggXsoAMCAQICE0kAKtabnHeoPU0ic54AAAAq1pswDQYJKoZIhvcNAQEMBQAwVzELMAkGA1UEBhMCVVMxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9zb2Z0IFRMUyBHMiBSU0EgQ0EgT0NTUCAxMDAeFw0yNjA1MTEyMjQ2MjhaFw0yNjA2MTAyMjQ2MjhaMIGVMQswCQYDVQQGEwJVUzELMAkGA1UECBMCV0ExEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjFHMEUGA1UEAxM+YmM2MjQ5MWE4MWEzMzU0MzZjZGMwNGNlLm1zcGtpdjIudGVzdC1vbmVjZXJ0LnNvdmNsb3VkLWNvcmUuZnIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA4SLeAcgkVO+Lul7I7+PO7gYUgH9upXaW/iD8nwyTMC/a9E95EBxjLVveRsIIAjkmeL8m+2MOfcp8WLBDnYHvSrPPCEtbiZ0KVDUyCDVtXD8193ZjfS8moVc4YlSZmUN+OT7x12DKoE7SeFlnTnNIY58NWJkiJqkcdhdyBPog4ViNvVYunPW+nouEKu2nItKiVO0ELivEXoFvkBiCFd4qXGQt16FcF6sC+aIVFVhnuTOkH8tJw1A4DAYuWCYx+X74w8lgSuahp2wihAqoPlbfZj2nl4k2+xMpgpUOgryfPPI9hi15qOBxDKqpdRfktuRSAMmsyzcx3olY4gkM2VMdAgMBAAGjggOIMIIDhDAbBgkrBgEEAYI3FQoEDjAMMAoGCCsGAQUFBwMBMDwGCSsGAQQBgjcVBwQvMC0GJSsGAQQBgjcVCIe91xuB5+tGgoGdLo7QDIfw2h1dhoafUYLR01QCAWQCASEwggELBggrBgEFBQcBAQSB/jCB+zBhBggrBgEFBQcwAoZVaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUTFMlMjBHMiUyMFJTQSUyMENBJTIwT0NTUCUyMDEwLmNydDBnBggrBgEFBQcwAoZbaHR0cDovL2NhaXNzdWVycy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUTFMlMjBHMiUyMFJTQSUyMENBJTIwT0NTUCUyMDEwLmNydDAtBggrBgEFBQcwAYYhaHR0cDovL29uZW9jc3AubWljcm9zb2Z0LmNvbS9vY3NwMB0GA1UdDgQWBBQjdQxv62GrPdjAiEBc14GPmFly3TAOBgNVHQ8BAf8EBAMCBaAwSQYDVR0RBEIwQII+YmM2MjQ5MWE4MWEzMzU0MzZjZGMwNGNlLm1zcGtpdjIudGVzdC1vbmVjZXJ0LnNvdmNsb3VkLWNvcmUuZnIwDAYDVR0TAQH/BAIwADCB8QYDVR0fBIHpMIHmMIHjoIHgoIHdhmxodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9wYXJ0aXRpb24vTWljcm9zb2Z0JTIwVExTJTIwRzIlMjBSU0ElMjBDQSUyME9DU1AlMjAxMF9QYXJ0aXRpb24wMDA0Ni5jcmyGbWh0dHA6Ly9jcmwyLm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9wYXJ0aXRpb24vTWljcm9zb2Z0JTIwVExTJTIwRzIlMjBSU0ElMjBDQSUyME9DU1AlMjAxMF9QYXJ0aXRpb24wMDA0Ni5jcmwwZgYDVR0gBF8wXTAIBgZngQwBAgIwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTAfBgNVHSMEGDAWgBTQTIPRjnEuPTSx/5t5LI501OJ4BjATBgNVHSUEDDAKBggrBgEFBQcDAQAA";
        let bytes = STANDARD.decode(entry).unwrap();
        let bytes = Bytes::from(bytes);
    }

    #[test]
    fn test_parse_leaf_cert_domains_timestamp() {}
}
