// Copyright (c) 2026 Microsoft Corporation
//
// SPDX-License-Identifier: BSD-2-Clause-Patent

//! Shared SPDM handshake building-blocks for the migration (MSK exchange)
//! and rebinding requester/responder paths.
//!
//! Two paths in this crate (`spdm_requester_transfer_msk` /
//! `spdm_requester_rebind_old` and the responder counterparts) run the same
//! SPDM-layer dance with only the two VDM-defined steps differing. This
//! module factors out the parts that are identical so each path only
//! supplies the bits that genuinely differ between MSK exchange and
//! rebinding.

use alloc::boxed::Box;
use alloc::vec::Vec;
use codec::{Codec, Writer};
use spdmlib::{
    error::{SpdmStatus, SPDM_STATUS_BUFFER_FULL},
    protocol::SpdmMeasurementSummaryHashType,
    requester::RequesterContext,
};
use zeroize::Zeroize;

use crate::spdm::{
    spdm_req::send_and_receive_pub_key,
    spdm_rsp::{rsp_handle_message, ResponderContextEx},
    SpdmAppContextData,
};

/// Run the shared SPDM requester prelude: version → capability → algorithm →
/// `send_and_receive_pub_key` → key_exchange. Returns the negotiated
/// `session_id` for the caller to use in subsequent VDM steps and the
/// final finish / end_session calls.
pub(super) async fn requester_handshake_prelude(
    spdm_requester: &mut RequesterContext,
) -> Result<u32, SpdmStatus> {
    Box::pin(spdm_requester.send_receive_spdm_version()).await?;
    Box::pin(spdm_requester.send_receive_spdm_capability()).await?;
    Box::pin(spdm_requester.send_receive_spdm_algorithm()).await?;
    Box::pin(send_and_receive_pub_key(spdm_requester)).await?;
    Box::pin(spdm_requester.send_receive_spdm_key_exchange(
        0xff,
        SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone,
    ))
    .await
}

/// Drive the SPDM responder message loop with a caller-provided
/// `SpdmAppContextData` payload and `peer_data` quote buffer.
///
/// Steps performed in order:
/// 1. Stash `peer_data` on `spdm_responder_ex` (read by VDM handlers via
///    `upcast_mut`).
/// 2. Encode `app_context` into the responder's `app_context_data_buffer`
///    (read by VDM handlers).
/// 3. Run `rsp_handle_message` until the session ends.
/// 4. Zeroize the `app_context_data_buffer` on the happy path. (Error paths
///    return early without clearing — matches the pre-existing behavior of
///    both `spdm_responder_transfer_msk` and `spdm_responder_rebind_new`.)
///
/// Callers that need to expose extra context to VDM handlers (e.g. setting
/// `spdm_responder_ex.info = RebindInformation(..)`) must do so before
/// invoking this helper.
pub(super) async fn run_responder_message_loop(
    spdm_responder_ex: &mut ResponderContextEx<'_>,
    peer_data: Vec<u8>,
    app_context: SpdmAppContextData,
) -> Result<(), SpdmStatus> {
    spdm_responder_ex.peer_data = peer_data;

    let spdm_responder = &mut spdm_responder_ex.responder_context;
    let mut writer = Writer::init(&mut spdm_responder.common.app_context_data_buffer);
    app_context
        .encode(&mut writer)
        .map_err(|_| SPDM_STATUS_BUFFER_FULL)?;

    Box::pin(rsp_handle_message(spdm_responder)).await?;
    spdm_responder.common.app_context_data_buffer.zeroize();

    Ok(())
}
