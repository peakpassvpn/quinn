use std::collections::VecDeque;
use std::fmt::{Debug, Display, Formatter};

use super::min_max::MinMax;
use crate::{Duration, Instant, packet::SpaceId};

/// The bandwidth BBR models: a windowed maximum of delivery-rate samples
///
/// Each ACK gives one sample, from the newest packet it acknowledges: the bytes delivered since
/// that packet was sent, over the longer of the time it took to send them and the time it took
/// to acknowledge them, as quiche's `BandwidthSampler` and Linux's `tcp_rate.c` take it
/// (draft-cheng-iccrg-delivery-rate-estimation). A rate over the time between two ACKs alone
/// reads low when one ACK covers many packets, and high when ACKs bunch.
#[derive(Clone, Debug)]
pub(crate) struct BandwidthEstimation {
    /// Bytes delivered, the draft's `C.delivered`
    total_acked: u64,
    /// When `total_acked` last grew, `C.delivered_time`
    delivered_time: Option<Instant>,
    /// When the newest packet the last ACK acknowledged was sent, `C.first_send_time`
    first_sent_time: Option<Instant>,
    /// No packet is in flight: the next one sent starts a new sampling interval
    idle: bool,
    /// While non-zero, the sender ran out of data before `total_acked` passes it, and packets
    /// sent until then are app-limited, `C.app_limited`
    app_limited_until: u64,
    /// Application-data packets in flight, in the order they were sent
    sent: VecDeque<Sent>,
    /// The newest packet the ACK being processed acknowledges
    newest: Option<Sent>,
    max_filter: MinMax,
    acked_at_last_window: u64,
}

/// What a packet's ACK needs to take a sample: the sender's state when it was sent
#[derive(Clone, Copy, Debug)]
struct Sent {
    number: u64,
    time: Instant,
    delivered: u64,
    delivered_time: Instant,
    first_sent_time: Instant,
    app_limited: bool,
    /// Acknowledged or lost
    done: bool,
}

impl Default for BandwidthEstimation {
    fn default() -> Self {
        Self {
            total_acked: 0,
            delivered_time: None,
            first_sent_time: None,
            idle: true,
            app_limited_until: 0,
            sent: VecDeque::new(),
            newest: None,
            max_filter: MinMax::default(),
            acked_at_last_window: 0,
        }
    }
}

impl BandwidthEstimation {
    pub(crate) fn on_packet_sent(&mut self, now: Instant, number: u64, space: SpaceId) {
        if space != SpaceId::Data {
            return;
        }
        if self.idle {
            self.idle = false;
            self.first_sent_time = Some(now);
            self.delivered_time = Some(now);
        }
        self.sent.push_back(Sent {
            number,
            time: now,
            delivered: self.total_acked,
            delivered_time: self.delivered_time.unwrap_or(now),
            first_sent_time: self.first_sent_time.unwrap_or(now),
            app_limited: self.app_limited_until != 0,
            done: false,
        });
    }

    pub(crate) fn on_ack(&mut self, now: Instant, bytes: u64, number: u64, space: SpaceId) {
        self.total_acked += bytes;
        self.delivered_time = Some(now);
        let Some(sent) = self.find(number, space) else {
            return;
        };
        sent.done = true;
        let sent = *sent;
        if self
            .newest
            .is_none_or(|newest| (sent.time, sent.number) > (newest.time, newest.number))
        {
            self.newest = Some(sent);
            self.first_sent_time = Some(sent.time);
        }
    }

    pub(crate) fn on_packet_lost(&mut self, number: u64, space: SpaceId) {
        if let Some(sent) = self.find(number, space) {
            sent.done = true;
        }
    }

    fn find(&mut self, number: u64, space: SpaceId) -> Option<&mut Sent> {
        if space != SpaceId::Data {
            return None;
        }
        let index = self
            .sent
            .binary_search_by_key(&number, |sent| sent.number)
            .ok()?;
        Some(&mut self.sent[index])
    }

    /// Packets whose sending is remembered
    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.sent.len()
    }

    pub(crate) fn bytes_acked_this_window(&self) -> u64 {
        self.total_acked - self.acked_at_last_window
    }

    /// Takes the ACK's sample, unless its interval is shorter than `min_rtt`: over less than a
    /// round trip, ACK compression passes for bandwidth.
    pub(crate) fn end_acks(
        &mut self,
        round: u64,
        app_limited: bool,
        in_flight: u64,
        largest_acked: Option<u64>,
        space: SpaceId,
        min_rtt: Duration,
    ) {
        self.acked_at_last_window = self.total_acked;
        if self.app_limited_until != 0 && self.total_acked > self.app_limited_until {
            self.app_limited_until = 0;
        }
        if app_limited {
            self.app_limited_until = (self.total_acked + in_flight).max(1);
        }
        self.idle = in_flight == 0;
        // A packet more than the packet threshold below the largest acknowledged is acknowledged,
        // lost, or acknowledged while a path was being validated and so never reported: no ACK
        // will ask for it again.
        let below = match (space, largest_acked) {
            (SpaceId::Data, Some(largest)) => largest.saturating_sub(PACKET_THRESHOLD),
            _ => 0,
        };
        while self
            .sent
            .front()
            .is_some_and(|sent| sent.done || sent.number < below)
        {
            self.sent.pop_front();
        }

        let (Some(newest), Some(delivered_time)) = (self.newest.take(), self.delivered_time) else {
            return;
        };
        let send_elapsed = newest
            .time
            .saturating_duration_since(newest.first_sent_time);
        let ack_elapsed = delivered_time.saturating_duration_since(newest.delivered_time);
        let interval = send_elapsed.max(ack_elapsed);
        if interval < min_rtt {
            return;
        }
        let Some(bandwidth) = Self::bw_from_delta(self.total_acked - newest.delivered, interval)
        else {
            return;
        };
        // Mirror Chromium/quiche's admission rule: non-app-limited samples
        // always feed the windowed max filter (feeding lower samples too is
        // what lets the window rotate and the estimate decay); app-limited
        // samples are admitted only when they RAISE the estimate, because a
        // path cannot fake delivering faster than it can, while a low
        // app-limited sample says nothing about capacity. Gating app-limited
        // samples out entirely left the filter empty on connections that are
        // app-limited from birth (a tunnel trickling below link rate), and a
        // zero estimate collapses the ack-aggregation epoch arithmetic into
        // unbounded excess_acked growth. Zero-rate artifacts are never
        // admitted.
        if bandwidth > 0 && (!newest.app_limited || bandwidth > self.max_filter.get()) {
            self.max_filter.update_max(round, bandwidth);
        }
    }

    pub(crate) fn get_estimate(&self) -> u64 {
        self.max_filter.get()
    }

    pub(crate) const fn bw_from_delta(bytes: u64, delta: Duration) -> Option<u64> {
        let window_duration_ns = delta.as_nanos();
        if window_duration_ns == 0 {
            return None;
        }
        let b_ns = bytes * 1_000_000_000;
        let bytes_per_second = b_ns / (window_duration_ns as u64);
        Some(bytes_per_second)
    }
}

/// RFC 9002's kPacketThreshold, quinn's default
const PACKET_THRESHOLD: u64 = 3;

impl Display for BandwidthEstimation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:.3} MB/s",
            self.get_estimate() as f32 / (1024 * 1024) as f32
        )
    }
}
