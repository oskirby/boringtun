// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::PacketData;
use crate::noise::errors::WireGuardError;
use portable_atomic::{AtomicU64, Ordering};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

pub struct Session {
    pub(crate) receiving_index: u32,
    sending_index: u32,
    receiver: LessSafeKey,
    sender: LessSafeKey,
    sending_key_counter: AtomicU64,
    receiving_key_counter: ReceivingKeyCounterValidator,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.receiving_index, self.sending_index
        )
    }
}

/// Where encrypted data resides in a data packet
const DATA_OFFSET: usize = 16;
/// The overhead of the AEAD
const AEAD_SIZE: usize = 16;

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
const N_WORDS: usize = 16; // Suffice to reorder 64*16 = 1024 packets; can be increased at will
const N_BITS: u64 = WORD_SIZE * N_WORDS as u64;
// The most significant bit used as a flag to indicate that the bitmap is being updated,
// and acts effectively as a spinlock.
const COUNTER_LOCK: u64 = 1u64 << (WORD_SIZE - 1);
const COUNTER_MASK: u64 = !COUNTER_LOCK;

#[derive(Debug, Default)]
struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: AtomicU64,
    /// Used to estimate packet loss
    receive_cnt: AtomicU64,
    bitmap: [AtomicU64; N_WORDS as usize],
}

impl ReceivingKeyCounterValidator {
    /// Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word].load(Ordering::Acquire) >> bit) & 1) == 1
    }

    /// Mark the packet as received, release the spinlock and return the verdict.
    #[inline(always)]
    fn mark_and_unlock(&self, idx: u64) -> Result<(), WireGuardError> {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        let previous = self.bitmap[word].fetch_or(1 << bit, Ordering::SeqCst);
        self.next.fetch_and(COUNTER_MASK, Ordering::SeqCst);
        if (previous >> bit) & 1 == 1 {
            Err(WireGuardError::DuplicateCounter)
        } else {
            Ok(())
        } 
    }

    /// Clear all the packets between prev and next.
    #[inline(always)]
    fn clear_range(&self, prev: u64, next: u64) {
        if next <= prev {
            return;
        }

        if next - prev >= N_BITS {
            // Too far ahead, clear all the bits
            for i in 0..N_WORDS {
                self.bitmap[i].store(0, Ordering::SeqCst);
            }
            return;
        }

        let prev_idx = (prev / WORD_SIZE) as usize;
        let prev_bit = 1u64 << (prev % WORD_SIZE);
        let next_idx = (next / WORD_SIZE) as usize;
        let next_bit = 1u64 << (next % WORD_SIZE);
        if next_idx == prev_idx {
            // The bits to clear all fit within a single word.
            let mask = !(next_bit - prev_bit);
            self.bitmap[prev_idx % N_WORDS].fetch_and(mask, Ordering::SeqCst);
        } else {
            // The bits to clear span multiple words.
            let mut mask: u64 = prev_bit - 1;
            for i in prev_idx..next_idx-1 {
                self.bitmap[i % N_WORDS].fetch_and(mask, Ordering::SeqCst);
                mask = 0;
            }
            self.bitmap[next_idx % N_WORDS].fetch_and(!(next_bit - 1), Ordering::SeqCst);
        }
    }

    /// Returns true if the counter was not yet received, and is not too far back
    /// This check is lock-free, but it can return a false positive in case a
    /// race condition occurs.
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= COUNTER_MASK {
            // Too many packets, counter would overflow.
            return Err(WireGuardError::InvalidCounter);
        }
        let next = self.next.load(Ordering::Acquire) & COUNTER_MASK;
        if counter >= next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if counter + N_BITS < next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if !self.check_bit(counter) {
            Ok(())
        } else {
            Err(WireGuardError::DuplicateCounter)
        }
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= COUNTER_MASK {
            // Too many packets, counter would overflow.
            return Err(WireGuardError::InvalidCounter);
        }

        let mut prev = self.next.load(Ordering::Acquire);
        loop {
            if (counter + N_BITS) < (prev & COUNTER_MASK) {
                // Drop if too far back that the packet would fall outside the bitmask.
                return Err(WireGuardError::InvalidCounter);
            }
            if prev & COUNTER_LOCK == COUNTER_LOCK {
                // Someone else has the spinlock. Try again.
                prev = self.next.load(Ordering::Acquire);
                continue;
            }
            if counter < prev {
                // This packet arrived out of order, just acquire the spinlock.
                match self.next.compare_exchange_weak(prev, prev | COUNTER_LOCK, Ordering::SeqCst, Ordering::Relaxed) {
                    Ok(_) => break,
                    Err(x) => prev = x,
                }
            } else {
                // This packet arrived in-order.
                // Acquire the spinlock, update the next packet counter, and clear bits that wrapped over.
                match self.next.compare_exchange_weak(prev, (counter+1) | COUNTER_LOCK, Ordering::SeqCst, Ordering::Relaxed) {
                    Ok(_) => {
                        self.clear_range(prev, counter);
                        break;
                    },
                    Err(x) => prev = x,
                }
            }
        }

        // And finally try to mark the packet, release the spinlock, and return the verdict.
        self.mark_and_unlock(counter)?;
        self.receive_cnt.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

impl Session {
    pub(super) fn new(
        local_index: u32,
        peer_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Session {
        Session {
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &receiving_key).unwrap(),
            ),
            sender: LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &sending_key).unwrap()),
            sending_key_counter: AtomicU64::new(0),
            receiving_key_counter: Default::default(),
        }
    }

    pub(super) fn local_index(&self) -> usize {
        self.receiving_index as usize
    }

    /// src - an IP packet from the interface
    /// dst - pre-allocated space to hold the encapsulating UDP packet to send over the network
    /// returns the size of the formatted packet
    pub(super) fn format_packet_data<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> &'a mut [u8] {
        if dst.len() < src.len() + super::DATA_OVERHEAD_SZ {
            panic!("The destination buffer is too small");
        }

        let sending_key_counter = self.sending_key_counter.fetch_add(1, Ordering::Relaxed) as u64;

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (counter, data) = rest.split_at_mut(8);

        message_type.copy_from_slice(&super::DATA.to_le_bytes());
        receiver_index.copy_from_slice(&self.sending_index.to_le_bytes());
        counter.copy_from_slice(&sending_key_counter.to_le_bytes());

        // TODO: spec requires padding to 16 bytes, but actually works fine without it
        let n = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&sending_key_counter.to_le_bytes());
            data[..src.len()].copy_from_slice(src);
            self.sender
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&[]),
                    &mut data[..src.len()],
                )
                .map(|tag| {
                    data[src.len()..src.len() + AEAD_SIZE].copy_from_slice(tag.as_ref());
                    src.len() + AEAD_SIZE
                })
                .unwrap()
        };

        &mut dst[..DATA_OFFSET + n]
    }

    /// packet - a data packet we received from the network
    /// dst - pre-allocated space to hold the encapsulated IP packet, to send to the interface
    ///       dst will always take less space than src
    /// return the size of the encapsulated packet on success
    pub(super) fn receive_packet_data<'a>(
        &self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        let ct_len = packet.encrypted_encapsulated_packet.len();
        if dst.len() < ct_len {
            // This is a very incorrect use of the library, therefore panic and not error
            panic!("The destination buffer is too small");
        }
        if packet.receiver_idx != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }
        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
        self.receiving_key_counter.will_accept(packet.counter)?;

        let ret = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&packet.counter.to_le_bytes());
            dst[..ct_len].copy_from_slice(packet.encrypted_encapsulated_packet);
            self.receiver
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&[]),
                    &mut dst[..ct_len],
                )
                .map_err(|_| WireGuardError::InvalidAeadTag)?
        };

        // After decryption is done, check counter again, and mark as received
        self.receiving_key_counter.mark_did_receive(packet.counter)?;
        Ok(ret)
    }

    /// Returns the estimated downstream packet loss for this session
    pub(super) fn current_packet_cnt(&self) -> (u64, u64) {
        let next = self.receiving_key_counter.next.load(Ordering::Relaxed) & COUNTER_MASK;
        let rx = self.receiving_key_counter.receive_cnt.load(Ordering::Relaxed);
        (next, rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_replay_counter() {
        let mut c: ReceivingKeyCounterValidator = Default::default();

        assert!(c.mark_did_receive(0).is_ok());
        assert!(c.mark_did_receive(0).is_err());
        assert!(c.mark_did_receive(1).is_ok());
        assert!(c.mark_did_receive(1).is_err());
        assert!(c.mark_did_receive(63).is_ok());
        assert!(c.mark_did_receive(63).is_err());
        assert!(c.mark_did_receive(15).is_ok());
        assert!(c.mark_did_receive(15).is_err());

        for i in 64..N_BITS + 128 {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3).is_ok());
        for i in 0..=N_BITS * 2 {
            assert!(matches!(
                c.will_accept(i),
                Err(WireGuardError::InvalidCounter)
            ));
            assert!(c.mark_did_receive(i).is_err());
        }
        for i in N_BITS * 2 + 1..N_BITS * 3 {
            assert!(c.will_accept(i).is_ok());
        }
        assert!(matches!(
            c.will_accept(N_BITS * 3),
            Err(WireGuardError::DuplicateCounter)
        ));

        for i in (N_BITS * 2 + 1..N_BITS * 3).rev() {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72 + 125).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 63).is_ok());

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_err());
    }
}
