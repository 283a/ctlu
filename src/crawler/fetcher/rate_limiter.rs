use std::{sync::Arc, time::Duration};

use tokio::{
    sync::Mutex,
    time::{Instant, sleep},
};

#[derive(Debug)]
struct InnerState {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl InnerState {
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();

        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);

        self.last_refill = now;
    }
}

#[derive(Debug, Clone)]
pub struct TokenBucketLimiter {
    inner_state: Arc<Mutex<InnerState>>,

}

impl TokenBucketLimiter {
    // rate is always in per second
    pub fn new(capacity: f64, refill_rate: f64) -> Self {
        Self {
            inner_state: Arc::new(Mutex::new(InnerState {
                tokens: capacity,
                capacity,
                refill_rate,
                last_refill: Instant::now(),
            })),
        }
    }

    pub async fn wait(&self) {
        loop{
            let wait_secs = {
                let mut inner_state = self.inner_state.lock().await;
                inner_state.refill();

                if inner_state.tokens >= 1.0 {
                    inner_state.tokens -= 1.0;
                    return ;
                }
                (1.0 - inner_state.tokens) / inner_state.refill_rate
            };

            sleep(Duration::from_secs_f64(wait_secs.max(0.0))).await;
        }
    }

    pub async fn backoff(&self) {
        let mut inner_state = self.inner_state.lock().await;
        inner_state.refill_rate = (inner_state.refill_rate * 0.9).max(0.0001);
    }

    pub async fn increase(&self) {
        let mut inner_state = self.inner_state.lock().await;
        inner_state.refill_rate = (inner_state.refill_rate + 0.1);
    }

    pub async fn get_refill_rate(&self) -> f64 {
        let inner_state = self.inner_state.lock().await;
        inner_state.refill_rate
    }
}
