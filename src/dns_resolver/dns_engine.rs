use anyhow::anyhow;
use anyhow::bail;
use governor::{Quota, RateLimiter};
use nonzero_ext::*;
use std::collections::HashMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicU16;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::sync::Semaphore;
use tokio::sync::oneshot;
use tokio::time::timeout;

pub struct LookupDualResult {
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    Timeout,        // by dnsengine
    IoError,        // network/socket errors
    NoAnswer,       // RCODE 0 no IPs found on A go AAAA. on AAAA no IP
    ServFail,       // RCODE 2 server failure, transient
    NxDomain,       // RCODE 3 non-existent domain, permanent
    Refused,        // RCODE 5 resolver refused, permanent
    OtherRcode(u8), // other RCODEs
    ParserError,
}

impl DnsError {
    fn is_server_failover_error(&self) -> bool {
        matches!(
            self,
            DnsError::ServFail | DnsError::Refused | DnsError::Timeout
        )
    }

    fn is_final_domain_error(&self) -> bool {
        matches!(self, DnsError::NxDomain)
    }
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for DnsError {}

impl From<std::io::Error> for DnsError {
    fn from(_: std::io::Error) -> Self {
        // losing original IoError but can use DNS error for return
        DnsError::IoError
    }
}

type RateLimiterType = RateLimiter<
    governor::state::NotKeyed,
    governor::state::InMemoryState,
    governor::clock::DefaultClock,
>;

pub struct DnsEnginePool {
    engines: Vec<DnsEngine>,
    next_engine: std::sync::atomic::AtomicUsize,
}

impl DnsEnginePool {
    pub async fn new() -> anyhow::Result<Self> {
        let mut engines: Vec<DnsEngine> = Vec::new();

        let mut engine: DnsEngine = DnsEngine::new("1.1.1.1").await?;
        engines.push(engine);
        let mut engine2: DnsEngine = DnsEngine::new("8.8.8.8").await?;
        engines.push(engine2);
        let mut engine3: DnsEngine = DnsEngine::new("1.0.0.1").await?;
        engines.push(engine3);
        let mut engine4: DnsEngine = DnsEngine::new("8.8.4.4").await?;
        engines.push(engine4);

        // quad9 is slow somehow?
        // oh blocks malicious domains i guess a lot of the domains are that though
        // let mut engine4: DnsEngine = DnsEngine::new("9.9.9.9").await?;
        // engines.push(engine4);
        // let mut engine5: DnsEngine = DnsEngine::new("9.9.9.10").await?;
        // engines.push(engine5);

        // these send tc for everything?

        // let mut engine5: DnsEngine = DnsEngine::new("185.222.222.222").await?;
        // engines.push(engine5);

        // let mut engine6: DnsEngine = DnsEngine::new("45.11.45.11").await?;
        // engines.push(engine6);

        Ok(DnsEnginePool {
            engines,
            next_engine: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    pub fn get_next_engine(&self) -> DnsEngine {
        let index = self
            .next_engine
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.engines.len();

        self.engines[index].clone()
    }

    pub async fn lookup(&self, domain: &str) -> anyhow::Result<Vec<IpAddr>> {
        // let engine = self.get_next_engine();
        // engine.lookup(domain).await
        let max_attempts = 4;
        for attempt in 0..max_attempts {
            let engine = self.get_next_engine();
            match engine.lookup(domain).await {
                Ok(ips) => {
                    return Ok(ips);
                }
                Err(e) => {
                    if e.is_final_domain_error() {
                        // nxdomain
                        return Err(e.into());
                    }
                    if e.is_server_failover_error() {
                        // next engine
                    }
                    if attempt == max_attempts - 1 {
                        return Err(e.into());
                    }
                }
            }
        }
        Err(anyhow::anyhow!(
            "DNS lookup failed on all engines and attempts."
        ))
    }

    pub async fn lookup_v4_v6(&self, domain: &str) -> anyhow::Result<LookupDualResult> {
        let max_attempts = 4;
        for attempt in 0..max_attempts {
            let engine = self.get_next_engine();
            // match engine.lookup(domain).await {
            //     Ok(ips) => {
            //         return Ok(ips);
            //     }
            //     Err(e) => {
            //         if e.is_final_domain_error() {
            //             // nxdomain
            //             return Err(e.into());
            //         }
            //         if e.is_server_failover_error() {
            //             // next engine
            //         }
            //         if attempt == max_attempts - 1 {
            //             return Err(e.into());
            //         }
            //     }
            // }

            match engine.lookup_v4_v6(domain).await {
                Ok(result) => return Ok(result),

                Err(e) => {
                    if e.is_final_domain_error() {
                        // nxdomain
                        return Err(e.into());
                    }
                    if e.is_server_failover_error() {
                        // next engine
                    }
                    if attempt == max_attempts - 1 {
                        return Err(e.into());
                    }
                }
            }
        }

        Err(anyhow::anyhow!(
            "DNS lookup failed on all engines and attempts."
        ))
    }
}

struct EngineState {
    // using a struct here so there is only one arc pointer/reference
    query_throttle: Semaphore,
    // next_id: Mutex<u16>,
    next_id: AtomicU16,
    pending: Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>,
    rate_limiter: Arc<RateLimiterType>,
}

#[derive(Clone)]
pub struct DnsEngine {
    socket: Arc<UdpSocket>,
    state: Arc<EngineState>,
}

impl DnsEngine {
    const MAX_CONCURRENCY: usize = 200;
    const MAX_LOOKUP_RETRIES: usize = 3;
    const LOOKUP_TIMEOUT_MS: u64 = 500;
    const TARGET_QPS: u32 = 740;

    // it should be possible to get to the desired speed with just one socket and remote resolver
    // but simply adding more remote resolver and distributing the queries over multiple resolver achieves the performance needed
    pub async fn new(ip_addr: &'static str) -> anyhow::Result<Self> {
        let socket: Arc<UdpSocket> = Arc::new(UdpSocket::bind(("0.0.0.0", 0)).await?);
        socket.connect((ip_addr, 53)).await?;

        let quota = Quota::per_second(nonzero!(Self::TARGET_QPS));
        let rate_limiter = Arc::new(RateLimiter::direct(quota));

        let state = Arc::new(EngineState {
            query_throttle: Semaphore::new(Self::MAX_CONCURRENCY),
            next_id: AtomicU16::new(0),
            pending: Mutex::new(HashMap::new()),
            rate_limiter: rate_limiter,
        });

        let engine: DnsEngine = DnsEngine {
            socket: socket.clone(),
            state: state.clone(),
        };

        {
            let receiver_socket: Arc<UdpSocket> = socket.clone();
            let receiver_state: Arc<EngineState> = state.clone();

            tokio::spawn(async move {
                let mut response_buffer: Vec<u8> = vec![0u8; 4096];

                loop {
                    let bytes_received = match receiver_socket.recv(&mut response_buffer).await {
                        Ok(n) if n >= 12 => n,
                        Ok(_) => continue,
                        Err(_) => break,
                    };

                    let id = u16::from_be_bytes([response_buffer[0], response_buffer[1]]);

                    let tx_response = {
                        let mut pending_lock = receiver_state.pending.lock().await;
                        pending_lock.remove(&id)
                    };

                    if let Some(tx_response) = tx_response {
                        let _ = tx_response.send(response_buffer[..bytes_received].to_vec());
                    }
                }
            });
        }

        Ok(engine)
    }

    pub async fn lookup_old(&self, domain: &str) -> anyhow::Result<Vec<IpAddr>> {
        // semaphore permit for max concurrency limit
        let permit = self
            .state
            .query_throttle
            .acquire()
            .await
            .expect("Semaphore closed");

        let result = async {
            let mut last_error: Option<anyhow::Error> = None;

            // retry for package loss
            for attempt in 1..=Self::MAX_LOOKUP_RETRIES {
                self.state.rate_limiter.until_ready().await;

                let query_id = self.state.next_id.fetch_add(1, Ordering::Relaxed);

                let (tx_response, rx_response) = oneshot::channel::<Vec<u8>>();

                {
                    // register id in hashmap
                    let mut pending_lock = self.state.pending.lock().await;
                    pending_lock.insert(query_id, tx_response);
                }

                let current_attempt_result = async {
                    let labels = fqdn_parser(domain)?;
                    let query_package = create_question_package(query_id, labels, 1).unwrap();
                    let _bytes_sent = self.socket.send(&query_package).await?;

                    let response_result =
                        timeout(Duration::from_millis(Self::LOOKUP_TIMEOUT_MS), rx_response).await;

                    // cleanup pending entry
                    // critical for timed out packages
                    {
                        let mut pending_lock = self.state.pending.lock().await;
                        pending_lock.remove(&query_id);
                    }

                    let response_bytes: Vec<u8> = match response_result {
                        Ok(Ok(response)) => response,
                        Err(_) => {
                            // timeout
                            bail!("Query id {} timed out, attempt {}", query_id, attempt)
                        }
                        Ok(Err(_)) => {
                            // sender dropped
                            bail!("Response channel dropped id {}", query_id)
                        }
                    };
                    parse_answer(response_bytes).map_err(|e| anyhow!(format!("{:?}", e)))
                }
                .await;

                match current_attempt_result {
                    Ok(ips) => return Ok(ips),
                    Err(e) => {
                        last_error = Some(e);
                        if attempt == Self::MAX_LOOKUP_RETRIES {
                            break;
                        }
                        // slight delay before next retry to avoid hammering (could remove not sure)
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            Err(last_error.unwrap_or_else(|| anyhow!("Failed to resolve after all retries.")))
        }
        .await;

        drop(permit);
        result
    }

    pub async fn lookup(&self, domain: &str) -> Result<Vec<IpAddr>, DnsError> {
        let permit = self
            .state
            .query_throttle
            .acquire()
            .await
            .expect("Semaphore closed");

        let result = async {
            match self.attempt_query(domain, 1).await {
                Ok(ips) => return Ok(ips),
                Err(DnsError::NoAnswer) => {}
                Err(e) => return Err(e),
            }

            match self.attempt_query(domain, 28).await {
                Ok(ips) => Ok(ips),
                Err(e) => Err(e),
            }
        }
        .await;

        drop(permit);
        result
    }

    pub async fn lookup_v4_v6(&self, domain: &str) -> Result<LookupDualResult, DnsError> {
        let permit = self
            .state
            .query_throttle
            .acquire()
            .await
            .expect("Semaphore closed");

        let (v4_result, v6_result) = tokio::join!(
            self.attempt_query(domain, 1),
            self.attempt_query(domain, 28)
        );

        let mut result = LookupDualResult {
            v4: Vec::new(),
            v6: Vec::new(),
        };

        match v4_result {
            Ok(ips) => {
                result.v4 = ips
                    .into_iter()
                    .filter_map(|ip| {
                        if let IpAddr::V4(ipv4) = ip {
                            Some(ipv4)
                        } else {
                            None
                        }
                    })
                    .collect();
            }
            Err(DnsError::NoAnswer) => {}
            Err(e) if e.is_final_domain_error() => return Err(e),
            Err(_e) => {}
        }

        match v6_result {
            Ok(ips) => {
                result.v6 = ips
                    .into_iter()
                    .filter_map(|ip| {
                        if let IpAddr::V6(ipv6) = ip {
                            Some(ipv6)
                        } else {
                            None
                        }
                    })
                    .collect();
            }
            Err(DnsError::NoAnswer) => {}
            Err(e) if e.is_final_domain_error() => return Err(e),
            Err(_e) => {}
        }

        if result.v4.is_empty() && result.v6.is_empty() {
            return Err(DnsError::NoAnswer);
        }

        drop(permit);
        Ok(result)
    }

    async fn attempt_query(
        &self,
        domain: &str,
        query_type: u16,
    ) -> anyhow::Result<Vec<IpAddr>, DnsError> {
        let last_error: DnsError = DnsError::IoError;
        for attempt in 1..=Self::MAX_LOOKUP_RETRIES {
            self.state.rate_limiter.until_ready().await;

            let (tx_response, rx_response) = oneshot::channel::<Vec<u8>>();
            let last_error;

            let query_id = {
                let mut pending_lock = self.state.pending.lock().await;

                loop {
                    let id = self.state.next_id.fetch_add(1, Ordering::Relaxed);
                    if !pending_lock.contains_key(&id) {
                        pending_lock.insert(id, tx_response);
                        break id;
                    }
                }
            };

            let current_attempt_result = async {
                // map the error to parse error can be done cleaner
                let labels = fqdn_parser(domain).map_err(|_| DnsError::ParserError)?;
                // this unwrap is not clean
                let query_package = create_question_package(query_id, labels, query_type).unwrap();
                let _bytes_sent = self.socket.send(&query_package).await?;

                let response_result =
                    timeout(Duration::from_millis(Self::LOOKUP_TIMEOUT_MS), rx_response).await;

                // cleanup pending entry
                // critical for timed out packages
                {
                    let mut pending_lock = self.state.pending.lock().await;
                    pending_lock.remove(&query_id);
                }

                let response_bytes = match response_result {
                    Ok(Ok(response)) => response,
                    Err(_) => return Err(DnsError::Timeout),
                    Ok(Err(_)) => {
                        // should only happen if response channel is dropped
                        return Err(DnsError::IoError);
                    }
                };
                parse_answer(response_bytes)
            }
            .await;

            match current_attempt_result {
                Ok(ips) => return Ok(ips),
                Err(e) => {
                    last_error = e;
                    if last_error.is_final_domain_error()
                        || matches!(last_error, DnsError::NoAnswer)
                    {
                        return Err(last_error);
                    }

                    if attempt == Self::MAX_LOOKUP_RETRIES {
                        return Err(last_error);
                    }

                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        Err(last_error)
    }
}

pub fn create_question_package(id: u16, question: Vec<String>, qtype: u16) -> Option<Vec<u8>> {
    // serializes question package
    // reserves space on heap with still length 0
    let mut packet: Vec<u8> = Vec::with_capacity(512);

    // Header
    // 0x00 for hex
    // 0b0000_0000 for a byte in binary

    // ID Packet Identifier 16 bit 2 byte
    // test id = 1
    // packet.push(0b0000_0000);
    // packet.push(0b0000_0001);
    packet.extend_from_slice(&id.to_be_bytes());

    // flags
    // QR Response 1 bit 0 for queries, 1 for response
    // OPCODE Operation Code 4 bit typically 0
    // AA Authoritative Answer 1 bit. 1 for authoritative server so caching server is 0
    // TC Truncated Message 1 bit. 1 if message length exceeds 512 bytes.
    // RD Recursion Desired 1 bit.
    packet.push(0b0000_0001);

    // RA Recursion Available 1 bit.
    // Z Reserved 3 bits. now DNSSEC
    // RCODE Response Code 4 bits. set by server status of response.
    packet.push(0b0000_0000);

    // QDCOUNT Question Count 16 bits. number of questions
    packet.push(0b0000_0000);
    packet.push(0b0000_0001);

    // ANCOUNT Answer Count 16 bits. number of answers
    packet.push(0b0000_0000);
    packet.push(0b0000_0000);

    // NSCOUNT Authority Count 16 bits. number of authority
    packet.push(0b0000_0000);
    packet.push(0b0000_0000);

    // ARCOUNT Additional Count 16 bits. number of additional
    packet.push(0b0000_0000);
    packet.push(0b0000_0000);

    // Name
    // Question len of label then label len of next label then label ...
    for label in &question {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    // TODO: maybe change to fqdn parser later so last zone is the zero byte ("") empty string is zero byte
    //
    // 0 to end label sequence
    packet.push(0);

    // Q Type 2 byte int. record type
    // A 1. AAAA 28
    // packet.push(0b0000_0000);
    // packet.push(0b0000_0001);

    packet.extend_from_slice(&qtype.to_be_bytes());

    // Q Class 2 byte int. class
    packet.push(0b0000_0000);
    packet.push(0b0000_0001);

    Some(packet)
}

pub fn parse_answer_old(response: Vec<u8>) -> Option<Vec<IpAddr>> {
    // deserializes the response package and returns the IPs.
    // could be a bottleneck at around 10k sequential parsing
    if response.len() < 12 {
        // len < 12 not enough bytes for a dns header
        return None;
    }

    // header
    // id 0,1
    // flags 2
    // flags 3
    // qdcount 4,5
    // ancount 6,7
    // nscount 8,9
    // arcount 10,11 (12 byte total)
    let id = u16::from_be_bytes([response[0], response[1]]);

    //check answer/question
    let qr = response[2] & 0b1000_0000;

    if qr == 0 {
        return None;
    }

    // RCODE
    // 0 = NoError
    // 1 = FormErr
    // 2 = ServFail
    // 3 = NXDOMAIN
    // 5 = Refused
    let rcode = response[3] & 0b0000_1111;
    // println!("RCode: {}", rcode);

    if rcode != 0 {
        return None;
    }

    // questions
    let qdcount: u16 = u16::from_be_bytes([response[4], response[5]]);

    // start after header
    let mut index = 12;

    let mut results: Vec<IpAddr> = Vec::new();

    let mut question_counter = 0;

    while question_counter < qdcount {
        let mut labels: Vec<String> = Vec::new();
        while response[index] != 0 {
            let label_length = response[index] as usize;
            index += 1;
            let label = &response[index..index + label_length];
            labels.push(String::from_utf8_lossy(label).into_owned());
            index += label_length;
        }
        // 0 byte
        index += 1;
        // println!("{}", labels.join("."));
        // type and class 4 byte
        index += 4;
        question_counter += 1;
    }
    // records: answers

    let ancount: u16 = u16::from_be_bytes([response[6], response[7]]);
    let mut answer_counter = 0;
    while answer_counter < ancount {
        // Parse answer record
        // Name (could be a pointer)
        let _name_start = index;
        let mut labels: Vec<String> = Vec::new();
        if response[index] & 0xC0 == 0xC0 {
            // pointer
            let _offset =
                (((response[index] & 0x3F) as usize) << 8) | (response[index + 1] as usize);
            // skip
            index += 2;
        } else {
            while response[index] != 0 {
                let label_length = response[index] as usize;
                index += 1;
                let label = &response[index..index + label_length];
                labels.push(String::from_utf8_lossy(label).into_owned());
                index += label_length;
            }
            index += 1;
        }

        // Type
        let answer_type = u16::from_be_bytes([response[index], response[index + 1]]);
        index += 2;
        // Class
        let _answer_class = u16::from_be_bytes([response[index], response[index + 1]]);
        index += 2;
        // TTL
        // let _ttl = u32::from_be_bytes([
        //     response[index],
        //     response[index + 1],
        //     response[index + 2],
        //     response[index + 3],
        // ]);
        index += 4;
        // Data length
        let data_len = u16::from_be_bytes([response[index], response[index + 1]]) as usize;
        index += 2;

        // Data
        if answer_type == 1 && data_len == 4 {
            // IPv4 primary availability IPv6 should be rare
            // IPv4 address
            let ip = Ipv4Addr::new(
                response[index],
                response[index + 1],
                response[index + 2],
                response[index + 3],
            );
            results.push(IpAddr::V4(ip));
        } else {
            // println!("Answer type {} not handled", answer_type);
        }
        index += data_len;
        answer_counter += 1;
    }

    Some(results)
}

pub fn parse_answer(response: Vec<u8>) -> Result<Vec<IpAddr>, DnsError> {
    // deserializes the response package and returns the IPs.
    // could be a bottleneck at around 10k sequential parsing
    if response.len() < 12 {
        // len < 12 not enough bytes for a dns header
        return Err(DnsError::ParserError);
    }

    // header
    // id 0,1
    // flags 2
    // flags 3
    // qdcount 4,5
    // ancount 6,7
    // nscount 8,9
    // arcount 10,11 (12 byte total)
    let _id = u16::from_be_bytes([response[0], response[1]]);

    //check answer/question
    let qr = response[2] & 0b1000_0000;

    if qr == 0 {
        // 1 in response would mean question
        return Err(DnsError::ParserError);
    }

    // TC bit
    let tc = response[2] & 0b0000_0010 != 0;
    if tc {
        return Err(DnsError::ServFail);
    }

    // RCODE
    // 0 = NoError
    // 1 = FormErr
    // 2 = ServFail
    // 3 = NXDOMAIN
    // 5 = Refused
    let rcode = response[3] & 0b0000_1111;

    match rcode {
        0 => {} // no error, continue parsing answers
        2 => return Err(DnsError::ServFail),
        3 => return Err(DnsError::NxDomain),
        5 => return Err(DnsError::Refused),
        _ => return Err(DnsError::OtherRcode(rcode)),
    }

    // questions
    let qdcount: u16 = u16::from_be_bytes([response[4], response[5]]);

    // start after header
    let mut index = 12;

    let mut results: Vec<IpAddr> = Vec::new();

    let mut question_counter = 0;
    let response_length = response.len();

    while question_counter < qdcount {
        let mut labels: Vec<String> = Vec::new();
        while response[index] != 0 {
            if index >= response_length {
                return Err(DnsError::ParserError);
            }
            let label_length = response[index] as usize;
            index += 1;
            let label = &response[index..index + label_length];
            labels.push(String::from_utf8_lossy(label).into_owned());
            index += label_length;
        }
        // 0 byte
        index += 1;
        // type and class 4 byte
        index += 4;
        question_counter += 1;
    }

    // check index is within bounds before processing answers
    if index > response_length {
        return Err(DnsError::ParserError);
    }

    // records: answers
    let ancount: u16 = u16::from_be_bytes([response[6], response[7]]);
    let mut answer_counter = 0;
    while answer_counter < ancount {
        if index > response_length {
            return Err(DnsError::ParserError);
        }
        // Name (could be a pointer)
        let mut labels: Vec<String> = Vec::new();
        if response[index] & 0xC0 == 0xC0 {
            // pointer
            // do not need that pointer
            // let offset =
            //     (((response[index] & 0x3F) as usize) << 8) | (response[index + 1] as usize);
            // skip
            index += 2;
        } else {
            while response[index] != 0 {
                if index > response_length {
                    return Err(DnsError::ParserError);
                }
                let label_length = response[index] as usize;
                index += 1;
                let label = &response[index..index + label_length];
                labels.push(String::from_utf8_lossy(label).into_owned());
                index += label_length;
            }
            index += 1;
        }

        if index + 10 > response_length {
            return Err(DnsError::ParserError);
        }
        // type 2 byte
        let answer_type = u16::from_be_bytes([response[index], response[index + 1]]);
        index += 2;
        // class 2 byte
        let _answer_class = u16::from_be_bytes([response[index], response[index + 1]]);
        index += 2;

        // TTL 4 byte
        // let _ttl = u32::from_be_bytes([
        //     response[index],
        //     response[index + 1],
        //     response[index + 2],
        //     response[index + 3],
        // ]);
        index += 4;

        // Data length
        let data_len = u16::from_be_bytes([response[index], response[index + 1]]) as usize;
        index += 2;

        if index + data_len > response_length {
            return Err(DnsError::ParserError);
        }

        // Data
        if answer_type == 1 && data_len == 4 {
            // IPv4 primary availability IPv6 should be rare
            // IPv4 address A record
            let ip = Ipv4Addr::new(
                response[index],
                response[index + 1],
                response[index + 2],
                response[index + 3],
            );
            results.push(IpAddr::V4(ip));
        } else if answer_type == 28 && data_len == 16 {
            // IPv6 AAAA record
            let mut data = [0u8; 16];
            data.copy_from_slice(&response[index..index + 16]);
            let ip = Ipv6Addr::from(data);
            results.push(IpAddr::V6(ip));
        }
        index += data_len;
        answer_counter += 1;
    }

    if results.is_empty() {
        // RCODE was 0 (NoError), but no answers
        Err(DnsError::NoAnswer)
    } else {
        Ok(results)
    }
}

pub fn fqdn_parser(fqdn: &str) -> anyhow::Result<Vec<String>> {
    // split the FQDN by '.' and filter out any empty labels
    let labels: Vec<String> = fqdn
        .split('.')
        .filter(|label| !label.is_empty())
        .map(String::from)
        .collect();

    if labels.is_empty() {
        bail!("FQDN must contain at least one label");
    }

    // Check each label for valid length
    let mut total_length = 0;
    for label in &labels {
        let len = label.len();
        if len == 0 || len > 63 {
            bail!("invalid label length [1..63]");
        }
        total_length += len + 1; // +1 for the length byte
    }
    total_length += 1; // for the final zero byte

    if total_length > 255 {
        bail!("total domain length exceeds 255 bytes");
    }

    Ok(labels)
}
