// Copyright (c) 2023 Intel Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent
use super::timer::*;
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
    time::Duration,
};
static SYS_TICK: AtomicU64 = AtomicU64::new(0);
const INTERVAL: u32 = 1;

pub struct TimeoutError;

// Non-AzCVMEmu: initialize APIC timer and use custom Timer future
#[cfg(not(feature = "AzCVMEmu"))]
pub fn init_sys_tick() {
    init_timer();
    set_timer_callback(timer_callback);
    schedule_timeout(INTERVAL);
}

// AzCVMEmu: no-op init
#[cfg(feature = "AzCVMEmu")]
pub fn init_sys_tick() {}

#[cfg(not(feature = "AzCVMEmu"))]
fn timer_callback() {
    SYS_TICK
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
        .unwrap();
    schedule_timeout(INTERVAL);
}

#[cfg(not(feature = "AzCVMEmu"))]
fn now() -> u64 {
    SYS_TICK.load(Ordering::SeqCst)
}

/// Runs a given future with a timeout.
#[cfg(not(feature = "AzCVMEmu"))]
pub async fn with_timeout<F: Future>(timeout: Duration, fut: F) -> Result<F::Output, TimeoutError> {
    use futures_util::{
        future::{select, Either},
        pin_mut,
    };
    pin_mut!(fut);
    let timeout_fut = Timer::after(timeout);
    match select(fut, timeout_fut).await {
        Either::Left((r, _)) => Ok(r),
        Either::Right(_) => Err(TimeoutError),
    }
}

/// AzCVMEmu: delegate timeout to Tokio's timer
#[cfg(feature = "AzCVMEmu")]
pub async fn with_timeout<F: Future>(timeout: Duration, fut: F) -> Result<F::Output, TimeoutError> {
    match tokio::time::timeout(timeout, fut).await {
        Ok(v) => Ok(v),
        Err(_elapsed) => Err(TimeoutError),
    }
}

#[cfg(not(feature = "AzCVMEmu"))]
pub struct Timer {
    expires_at: u128,
    yielded_once: bool,
}

#[cfg(not(feature = "AzCVMEmu"))]
impl Timer {
    /// Expire after specified duration.
    pub fn after(duration: Duration) -> Self {
        Self {
            expires_at: now() as u128 + duration.as_millis(),
            yielded_once: false,
        }
    }
}

#[cfg(not(feature = "AzCVMEmu"))]
impl Unpin for Timer {}

#[cfg(not(feature = "AzCVMEmu"))]
impl Future for Timer {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.yielded_once && self.expires_at <= now() as u128 {
            Poll::Ready(())
        } else {
            self.yielded_once = true;
            Poll::Pending
        }
    }
}
