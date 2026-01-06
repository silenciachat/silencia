use rand::Rng;
use std::time::Duration;
use tokio::time::{sleep, Instant};

/// Timing jitter for message sends
pub struct TimingJitter {
    min_delay: Duration,
    max_delay: Duration,
}

impl TimingJitter {
    pub fn new(min_ms: u64, max_ms: u64) -> Self {
        Self {
            min_delay: Duration::from_millis(min_ms),
            max_delay: Duration::from_millis(max_ms),
        }
    }

    pub fn default_jitter() -> Self {
        Self::new(10, 100)
    }

    pub async fn apply(&self) {
        let jitter_ms = rand::thread_rng()
            .gen_range(self.min_delay.as_millis()..=self.max_delay.as_millis())
            as u64;

        sleep(Duration::from_millis(jitter_ms)).await;
    }

    pub fn jitter_duration(&self) -> Duration {
        let jitter_ms = rand::thread_rng()
            .gen_range(self.min_delay.as_millis()..=self.max_delay.as_millis())
            as u64;

        Duration::from_millis(jitter_ms)
    }
}

/// Delayed ACK scheduler
pub struct DelayedAck {
    max_delay: Duration,
    pending: Vec<(Instant, Vec<u8>)>,
}

impl DelayedAck {
    pub fn new(max_delay_ms: u64) -> Self {
        Self {
            max_delay: Duration::from_millis(max_delay_ms),
            pending: Vec::new(),
        }
    }

    pub fn schedule_ack(&mut self, message_id: Vec<u8>) {
        let send_time = Instant::now() + self.max_delay;
        self.pending.push((send_time, message_id));
    }

    pub fn get_ready_acks(&mut self) -> Vec<Vec<u8>> {
        let now = Instant::now();

        let (ready, pending): (Vec<_>, Vec<_>) =
            self.pending.drain(..).partition(|(time, _)| *time <= now);

        self.pending = pending;

        ready.into_iter().map(|(_, id)| id).collect()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_timing_jitter() {
        let jitter = TimingJitter::new(10, 50);

        let start = Instant::now();
        jitter.apply().await;
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_millis(10));
        assert!(elapsed <= Duration::from_millis(100));
    }

    #[test]
    fn test_delayed_ack() {
        let mut ack = DelayedAck::new(10);

        ack.schedule_ack(vec![1, 2, 3]);
        assert_eq!(ack.pending_count(), 1);

        let ready = ack.get_ready_acks();
        assert_eq!(ready.len(), 0);
    }

    #[tokio::test]
    async fn test_delayed_ack_timeout() {
        let mut ack = DelayedAck::new(50);

        ack.schedule_ack(vec![1, 2, 3]);

        sleep(Duration::from_millis(100)).await;

        let ready = ack.get_ready_acks();
        assert_eq!(ready.len(), 1);
    }
}
