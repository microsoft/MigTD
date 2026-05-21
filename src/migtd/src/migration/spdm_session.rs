// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Shared SPDM session-driving helpers used by both migration (MSK exchange)
//! and rebinding paths. Centralizes the common boilerplate of running the
//! SPDM body under a 60-second timeout and shutting down the transport.

use core::future::Future;
use core::ops::DerefMut;
use core::time::Duration;
use spdmlib::error::SpdmStatus;
use spdmlib::message::SpdmErrorCode;

use super::transport::{shutdown_transport, TransportType};
use super::MigrationResult;
use crate::driver::ticks::with_timeout;
use crate::spdm::SpdmDeviceIoArc;

type Result<T> = core::result::Result<T, MigrationResult>;

/// Timeout that wraps every SPDM session body (requester or responder).
pub(super) const SPDM_TIMEOUT: Duration = Duration::from_secs(60);

/// Standard error mapping for a failed `spdm::spdm_requester` /
/// `spdm::spdm_responder` transport setup.
pub(super) fn map_spdm_setup_err(mig_request_id: u64) -> MigrationResult {
    log::error!(
        migration_request_id = mig_request_id;
        "SPDM transport setup failed\n"
    );
    MigrationResult::SecureSessionError
}

/// Run an SPDM session `body` under [`SPDM_TIMEOUT`], then shut down the
/// transport associated with `io_ref`. Returns any value produced by `body`.
///
/// `body` is the already-constructed future returned by an SPDM exchange
/// function (e.g. `spdm_requester_transfer_msk`, `spdm_responder_rebind_new`).
/// The caller owns the SPDM context that `body` borrows; this helper only
/// drives `body` to completion and then takes the device-IO lock to invoke
/// `shutdown_transport`.
pub(super) async fn finalize_spdm_session<Fut, T>(
    body: Fut,
    io_ref: SpdmDeviceIoArc<TransportType>,
    mig_request_id: u64,
) -> Result<T>
where
    Fut: Future<Output = core::result::Result<T, SpdmStatus>>,
{
    let value = with_timeout(SPDM_TIMEOUT, body)
        .await
        .map_err(|e| {
            log::error!(
                migration_request_id = mig_request_id;
                "finalize_spdm_session: body timeout: {e:?}\n"
            );
            MigrationResult::from(e)
        })?
        .map_err(|e| {
            log::error!(
                migration_request_id = mig_request_id;
                "finalize_spdm_session: body error: {e:?}\n"
            );
            // Extract application error from SpdmStatus:
            // 1. Destination (local): error is VDM-encoded in status_code directly.
            let result = MigrationResult::from(e);
            if result != MigrationResult::SecureSessionError {
                return result; // VDM decode succeeded — local (destination) error
            }
            // 2. Source (remote): peer's error arrives as raw SPDM ERROR response
            //    stored in error_data. Extract app code from param2 byte.
            if let Some(ref ed) = e.error_data {
                if ed.length >= 4 && ed.data[2] == SpdmErrorCode::SpdmErrorVendorDefined.get_u8() {
                    if let Ok(mig_result) = MigrationResult::try_from(ed.data[3]) {
                        return mig_result;
                    }
                }
            }
            MigrationResult::SecureSessionError
        })?;

    let mut transport_lock = io_ref.lock();
    let transport = transport_lock.deref_mut();
    shutdown_transport(&mut transport.transport, mig_request_id).await?;

    Ok(value)
}
