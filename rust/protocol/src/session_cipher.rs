//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use pswoosh::keys::{PublicSwooshKey, SwooshKeyPair};
use rand::{CryptoRng, Rng};

use crate::consts::{MAX_FORWARD_JUMPS, MAX_UNACKNOWLEDGED_SESSION_AGE};
use crate::ratchet::{ChainKey, MessageKeyGenerator, UsePQRatchet};
use crate::state::{InvalidSessionError, SessionState};
use crate::{
    session, CiphertextMessage, CiphertextMessageType, Direction, IdentityKeyStore, KeyPair,
    KyberPayload, KyberPreKeyStore, PreKeySignalMessage, PreKeyStore, ProtocolAddress, PublicKey,
    Result, SessionRecord, SessionStore, SignalMessage, SignalProtocolError, SignedPreKeyStore, SwooshPreKeyStore,
};

pub async fn message_encrypt<R: Rng + CryptoRng>(
    ptext: &[u8],
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    now: SystemTime,
    csprng: &mut R,
) -> Result<CiphertextMessage> {
    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .ok_or_else(|| SignalProtocolError::SessionNotFound(remote_address.clone()))?;
    let session_state = session_record
        .session_state_mut()
        .ok_or_else(|| SignalProtocolError::SessionNotFound(remote_address.clone()))?;
    
    let chain_key = session_state.get_sender_chain_key()?;
    
    let (pqr_msg, pqr_key) = session_state.pq_ratchet_send(csprng).map_err(|e| {
        // Since we're sending, this must be an error with the state.
        SignalProtocolError::InvalidState(
            "message_encrypt",
            format!("post-quantum ratchet send error: {e}"),
        )
    })?;
    
    let message_keys = chain_key.message_keys().generate_keys(pqr_key);
    
    let sender_ephemeral = session_state.sender_ratchet_key()?;
    
    let previous_counter = session_state.previous_counter();
    let session_version = session_state
        .session_version()?
        .try_into()
        .map_err(|_| SignalProtocolError::InvalidSessionStructure("version does not fit in u8"))?;
    
    let local_identity_key = session_state.local_identity_key()?;
    let their_identity_key = session_state.remote_identity_key()?.ok_or_else(|| {
        SignalProtocolError::InvalidState(
            "message_encrypt",
            format!("no remote identity key for {remote_address}"),
        )
    })?;
    
    // Print the encryption key being used for this message
    /*
    println!("🔑 MESSAGE ENCRYPTION KEY (for {}): length={} bytes, first 8 bytes: {:02x?}", 
             remote_address, 
             message_keys.cipher_key().len(), 
             &message_keys.cipher_key()[..8]);
    */
    let ctext =
        signal_crypto::aes_256_cbc_encrypt(ptext, message_keys.cipher_key(), message_keys.iv())
            .map_err(|_| {
                log::error!("session state corrupt for {remote_address}");
                SignalProtocolError::InvalidSessionStructure("invalid sender chain message keys")
            })?;

    let message = if let Some(items) = session_state.unacknowledged_pre_key_message_items()? {
        let timestamp_as_unix_time = items
            .timestamp()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if items.timestamp() + MAX_UNACKNOWLEDGED_SESSION_AGE < now {
            log::warn!(
                "stale unacknowledged session for {remote_address} (created at {timestamp_as_unix_time})"
            );
            return Err(SignalProtocolError::SessionNotFound(remote_address.clone()));
        }

        let local_registration_id = session_state.local_registration_id();

        log::info!(
            "Building PreKeyWhisperMessage for: {} with preKeyId: {} (session created at {})",
            remote_address,
            items
                .pre_key_id()
                .map_or_else(|| "<none>".to_string(), |id| id.to_string()),
            timestamp_as_unix_time,
        );

        let message = SignalMessage::new(
            session_version,
            message_keys.mac_key(),
            Some(sender_ephemeral),
            None,
            chain_key.index(),
            previous_counter,
            &ctext,
            &local_identity_key,
            &their_identity_key,
            &pqr_msg,
        )?;

        let kyber_payload = items
            .kyber_pre_key_id()
            .zip(items.kyber_ciphertext())
            .map(|(id, ciphertext)| KyberPayload::new(id, ciphertext.into()));

        CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::new(
            session_version,
            local_registration_id,
            items.pre_key_id(),
            items.signed_pre_key_id(),
            kyber_payload,
            items.swoosh_pre_key_id(), // Include the Swoosh pre-key ID
            *items.base_key(),
            local_identity_key,
            message,
        )?)
    } else {
        CiphertextMessage::SignalMessage(SignalMessage::new(
            session_version,
            message_keys.mac_key(),
            Some(sender_ephemeral),
            None,
            chain_key.index(),
            previous_counter,
            &ctext,
            &local_identity_key,
            &their_identity_key,
            &pqr_msg,
        )?)
    };

    session_state.set_sender_chain_key(&chain_key.next_chain_key());

    // XXX why is this check after everything else?!!
    if !identity_store
        .is_trusted_identity(remote_address, &their_identity_key, Direction::Sending)
        .await?
    {
        log::warn!(
            "Identity key {} is not trusted for remote address {}",
            hex::encode(their_identity_key.public_key().public_key_bytes()),
            remote_address,
        );
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    // XXX this could be combined with the above call to the identity store (in a new API)
    identity_store
        .save_identity(remote_address, &their_identity_key)
        .await?;

    session_store
        .store_session(remote_address, &session_record)
        .await?;
    Ok(message)
    
}

pub async fn message_encrypt_swoosh<R: Rng + CryptoRng>(
    ptext: &[u8],
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    now: SystemTime,
    csprng: &mut R,
) -> Result<CiphertextMessage> {
    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .ok_or_else(|| SignalProtocolError::SessionNotFound(remote_address.clone()))?;
    let session_state = session_record
        .session_state_mut()
        .ok_or_else(|| SignalProtocolError::SessionNotFound(remote_address.clone()))?;
    
    let chain_key = session_state.get_sender_chain_key()?;
    // println!("🔑 Encryption SWOOSH chain key first 8 bytes: {:02x?}", &chain_key.key()[..8]);
    
    let (pqr_msg, pqr_key) = session_state.pq_ratchet_send(csprng).map_err(|e| {
        // Since we're sending, this must be an error with the state.
        SignalProtocolError::InvalidState(
            "message_encrypt",
            format!("post-quantum ratchet send error: {e}"),
        )
    })?;
    
    let message_keys = chain_key.message_keys().generate_keys(pqr_key);
    
    let sender_swoosh_ephemeral = session_state.sender_ratchet_swoosh_public_key()?;
    //println!("🔑 Swoosh ephemeral key first 8 bytes: {:02x?}", &sender_swoosh_ephemeral.public_key_bytes()[..8]);
    
    let previous_counter = session_state.previous_counter();
    let session_version = session_state
        .session_version()?
        .try_into()
        .map_err(|_| SignalProtocolError::InvalidSessionStructure("version does not fit in u8"))?;
    
    let local_identity_key = session_state.local_identity_key()?;
    let their_identity_key = session_state.remote_identity_key()?.ok_or_else(|| {
        SignalProtocolError::InvalidState(
            "message_encrypt",
            format!("no remote identity key for {remote_address}"),
        )
    })?;
    
    // Print the encryption key being used for this message
    /*
    println!("🔑 MESSAGE ENCRYPTION KEY (for {}): length={} bytes, first 8 bytes: {:02x?}", 
             remote_address, 
             message_keys.cipher_key().len(), 
             &message_keys.cipher_key()[..8]);
    */
    let ctext =
        signal_crypto::aes_256_cbc_encrypt(ptext, message_keys.cipher_key(), message_keys.iv())
            .map_err(|_| {
                log::error!("session state corrupt for {remote_address}");
                SignalProtocolError::InvalidSessionStructure("invalid sender chain message keys")
            })?;

    let message = if let Some(items) = session_state.unacknowledged_pre_key_message_items()? {
        let timestamp_as_unix_time = items
            .timestamp()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if items.timestamp() + MAX_UNACKNOWLEDGED_SESSION_AGE < now {
            log::warn!(
                "stale unacknowledged session for {remote_address} (created at {timestamp_as_unix_time})"
            );
            return Err(SignalProtocolError::SessionNotFound(remote_address.clone()));
        }

        let local_registration_id = session_state.local_registration_id();

        log::info!(
            "Building PreKeyWhisperMessage for: {} with preKeyId: {} (session created at {})",
            remote_address,
            items
                .pre_key_id()
                .map_or_else(|| "<none>".to_string(), |id| id.to_string()),
            timestamp_as_unix_time,
        );

        let message = SignalMessage::new(
            session_version,
            message_keys.mac_key(),
            None,
            Some(sender_swoosh_ephemeral),
            chain_key.index(),
            previous_counter,
            &ctext,
            &local_identity_key,
            &their_identity_key,
            &pqr_msg,
        )?;

        let kyber_payload = items
            .kyber_pre_key_id()
            .zip(items.kyber_ciphertext())
            .map(|(id, ciphertext)| KyberPayload::new(id, ciphertext.into()));

        CiphertextMessage::PreKeySignalMessage(PreKeySignalMessage::new(
            session_version,
            local_registration_id,
            items.pre_key_id(),
            items.signed_pre_key_id(),
            kyber_payload,
            items.swoosh_pre_key_id(), // Include the Swoosh pre-key ID
            *items.base_key(),
            local_identity_key,
            message,
        )?)
    } else {
        CiphertextMessage::SignalMessage(SignalMessage::new(
            session_version,
            message_keys.mac_key(),
            None,
            Some(sender_swoosh_ephemeral),
            chain_key.index(),
            previous_counter,
            &ctext,
            &local_identity_key,
            &their_identity_key,
            &pqr_msg,
        )?)
    };

    session_state.set_sender_chain_key(&chain_key.next_chain_key());

    // XXX why is this check after everything else?!!
    if !identity_store
        .is_trusted_identity(remote_address, &their_identity_key, Direction::Sending)
        .await?
    {
        log::warn!(
            "Identity key {} is not trusted for remote address {}",
            hex::encode(their_identity_key.public_key().public_key_bytes()),
            remote_address,
        );
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    // XXX this could be combined with the above call to the identity store (in a new API)
    identity_store
        .save_identity(remote_address, &their_identity_key)
        .await?;

    session_store
        .store_session(remote_address, &session_record)
        .await?;
    Ok(message)
    
}

#[allow(clippy::too_many_arguments)]
pub async fn message_decrypt<R: Rng + CryptoRng>(
    ciphertext: &CiphertextMessage,
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &dyn SignedPreKeyStore,
    kyber_pre_key_store: &mut dyn KyberPreKeyStore,
    swoosh_pre_key_store: &dyn SwooshPreKeyStore,
    csprng: &mut R,
    use_pq_ratchet: UsePQRatchet,
) -> Result<Vec<u8>> {
    match ciphertext {
        CiphertextMessage::SignalMessage(m) => {
            message_decrypt_signal(m, remote_address, session_store, identity_store, csprng).await
        }
        CiphertextMessage::PreKeySignalMessage(m) => {
            message_decrypt_prekey(
                m,
                remote_address,
                session_store,
                identity_store,
                pre_key_store,
                signed_pre_key_store,
                kyber_pre_key_store,
                swoosh_pre_key_store,
                csprng,
                use_pq_ratchet,
            )
            .await
        }
        _ => Err(SignalProtocolError::InvalidArgument(format!(
            "message_decrypt cannot be used to decrypt {:?} messages",
            ciphertext.message_type()
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn message_decrypt_prekey<R: Rng + CryptoRng>(
    ciphertext: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    pre_key_store: &mut dyn PreKeyStore,
    signed_pre_key_store: &dyn SignedPreKeyStore,
    kyber_pre_key_store: &mut dyn KyberPreKeyStore,
    swoosh_pre_key_store: &dyn SwooshPreKeyStore,
    csprng: &mut R,
    use_pq_ratchet: UsePQRatchet,
) -> Result<Vec<u8>> {
    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .unwrap_or_else(SessionRecord::new_fresh);

    // Make sure we log the session state if we fail to process the pre-key.
    let process_prekey_result = session::process_prekey(
        ciphertext,
        remote_address,
        &mut session_record,
        identity_store,
        pre_key_store,
        signed_pre_key_store,
        kyber_pre_key_store,
        swoosh_pre_key_store,
        use_pq_ratchet,
    )
    .await;

    let (pre_key_used, identity_to_save) = match process_prekey_result {
        Ok(result) => result,
        Err(e) => {
            let errs = [e];
            log::error!(
                "{}",
                create_decryption_failure_log(
                    remote_address,
                    &errs,
                    &session_record,
                    ciphertext.message()
                )?
            );
            let [e] = errs;
            return Err(e);
        }
    };

    let swoosh_key = ciphertext.swoosh_pre_key_id();

    let ptext = match swoosh_key {
        Some(_) => {
            decrypt_message_with_record_swoosh(
                remote_address,
                &mut session_record,
                ciphertext.message(),
                CiphertextMessageType::PreKey,
                identity_store.is_alice().await?,
            )?
        }
        None => {
            decrypt_message_with_record(
                remote_address,
                &mut session_record,
                ciphertext.message(),
                CiphertextMessageType::PreKey,
                csprng,
            )?
        }
    };

    identity_store
        .save_identity(
            identity_to_save.remote_address,
            identity_to_save.their_identity_key,
        )
        .await?;

    session_store
        .store_session(remote_address, &session_record)
        .await?;

    if let Some(pre_key_id) = pre_key_used.pre_key_id {
        pre_key_store.remove_pre_key(pre_key_id).await?;
    }

    if let Some(kyber_pre_key_id) = pre_key_used.kyber_pre_key_id {
        kyber_pre_key_store
            .mark_kyber_pre_key_used(kyber_pre_key_id)
            .await?;
    }

    Ok(ptext)
}

pub async fn message_decrypt_signal<R: Rng + CryptoRng>(
    ciphertext: &SignalMessage,
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .ok_or_else(|| SignalProtocolError::SessionNotFound(remote_address.clone()))?;

    let swoosh_key = ciphertext.sender_ratchet_swoosh_key();

    let ptext = match swoosh_key {
        Some(_) => {
            decrypt_message_with_record_swoosh(
                remote_address,
                &mut session_record,
                ciphertext,
                CiphertextMessageType::Whisper,
                identity_store.is_alice().await?,
            )?
        }
        None => {
            decrypt_message_with_record(
                remote_address,
                &mut session_record,
                ciphertext,
                CiphertextMessageType::Whisper,
                csprng,
            )?
        }
    };

    

    // Why are we performing this check after decryption instead of before?
    let their_identity_key = session_record
        .session_state()
        .expect("successfully decrypted; must have a current state")
        .remote_identity_key()
        .expect("successfully decrypted; must have a remote identity key")
        .expect("successfully decrypted; must have a remote identity key");

    if !identity_store
        .is_trusted_identity(remote_address, &their_identity_key, Direction::Receiving)
        .await?
    {
        log::warn!(
            "Identity key {} is not trusted for remote address {}",
            hex::encode(their_identity_key.public_key().public_key_bytes()),
            remote_address,
        );
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    identity_store
        .save_identity(remote_address, &their_identity_key)
        .await?;

    session_store
        .store_session(remote_address, &session_record)
        .await?;

    Ok(ptext)
}

fn create_decryption_failure_log(
    remote_address: &ProtocolAddress,
    mut errs: &[SignalProtocolError],
    record: &SessionRecord,
    ciphertext: &SignalMessage,
) -> Result<String> {
    fn append_session_summary(
        lines: &mut Vec<String>,
        idx: usize,
        state: std::result::Result<&SessionState, InvalidSessionError>,
        err: Option<&SignalProtocolError>,
    ) {
        let chains = state.map(|state| state.all_receiver_chain_logging_info());
        match (err, &chains) {
            (Some(err), Ok(chains)) => {
                lines.push(format!(
                    "Candidate session {} failed with '{}', had {} receiver chains",
                    idx,
                    err,
                    chains.len()
                ));
            }
            (Some(err), Err(state_err)) => {
                lines.push(format!(
                    "Candidate session {idx} failed with '{err}'; cannot get receiver chain info ({state_err})",
                ));
            }
            (None, Ok(chains)) => {
                lines.push(format!(
                    "Candidate session {} had {} receiver chains",
                    idx,
                    chains.len()
                ));
            }
            (None, Err(state_err)) => {
                lines.push(format!(
                    "Candidate session {idx}: cannot get receiver chain info ({state_err})",
                ));
            }
        }

        if let Ok(chains) = chains {
            for chain in chains {
                let chain_idx = match chain.1 {
                    Some(i) => i.to_string(),
                    None => "missing in protobuf".to_string(),
                };

                lines.push(format!(
                    "Receiver chain with sender ratchet public key {} chain key index {}",
                    hex::encode(chain.0),
                    chain_idx
                ));
            }
        }
    }

    let mut lines = vec![];

    lines.push(format!(
        "Message from {} failed to decrypt; sender ratchet public key {} message counter {}",
        remote_address,
        hex::encode(ciphertext.sender_ratchet_key().unwrap().public_key_bytes()),
        ciphertext.counter()
    ));

    if let Some(current_session) = record.session_state() {
        let err = errs.first();
        if err.is_some() {
            errs = &errs[1..];
        }
        append_session_summary(&mut lines, 0, Ok(current_session), err);
    } else {
        lines.push("No current session".to_string());
    }

    for (idx, (state, err)) in record
        .previous_session_states()
        .zip(errs.iter().map(Some).chain(std::iter::repeat(None)))
        .enumerate()
    {
        let state = match state {
            Ok(ref state) => Ok(state),
            Err(err) => Err(err),
        };
        append_session_summary(&mut lines, idx + 1, state, err);
    }

    Ok(lines.join("\n"))
}

fn decrypt_message_with_record<R: Rng + CryptoRng>(
    remote_address: &ProtocolAddress,
    record: &mut SessionRecord,
    ciphertext: &SignalMessage,
    original_message_type: CiphertextMessageType,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    debug_assert!(matches!(
        original_message_type,
        CiphertextMessageType::Whisper | CiphertextMessageType::PreKey
    ));
    let log_decryption_failure = |state: &SessionState, error: &SignalProtocolError| {
        // A warning rather than an error because we try multiple sessions.
        log::warn!(
            "Failed to decrypt {:?} message with ratchet key: {} and counter: {}. \
             Session loaded for {}. Local session has base key: {} and counter: {}. {}",
            original_message_type,
            hex::encode(ciphertext.sender_ratchet_key().unwrap().public_key_bytes()),
            ciphertext.counter(),
            remote_address,
            state
                .sender_ratchet_key_for_logging()
                .unwrap_or_else(|e| format!("<error: {e}>")),
            state.previous_counter(),
            error
        );
    };

    let mut errs = vec![];

    if let Some(current_state) = record.session_state() {
        let mut current_state = current_state.clone();
        let result = decrypt_message_with_state(
            CurrentOrPrevious::Current,
            &mut current_state,
            ciphertext,
            original_message_type,
            remote_address,
            csprng,
        );

        match result {
            Ok(ptext) => {
                log::info!(
                    "decrypted {:?} message from {} with current session state (base key {})",
                    original_message_type,
                    remote_address,
                    current_state
                        .sender_ratchet_key_for_logging()
                        .expect("successful decrypt always has a valid base key"),
                );
                record.set_session_state(current_state); // update the state
                return Ok(ptext);
            }
            Err(SignalProtocolError::DuplicatedMessage(_, _)) => {
                return result;
            }
            Err(e) => {
                log_decryption_failure(&current_state, &e);
                errs.push(e);
                match original_message_type {
                    CiphertextMessageType::PreKey => {
                        // A PreKey message creates a session and then decrypts a Whisper message
                        // using that session. No need to check older sessions.
                        log::error!(
                            "{}",
                            create_decryption_failure_log(
                                remote_address,
                                &errs,
                                record,
                                ciphertext
                            )?
                        );
                        // Note that we don't propagate `e` here; we always return InvalidMessage,
                        // as we would for a Whisper message that tried several sessions.
                        return Err(SignalProtocolError::InvalidMessage(
                            original_message_type,
                            "decryption failed",
                        ));
                    }
                    CiphertextMessageType::Whisper => {}
                    CiphertextMessageType::SenderKey | CiphertextMessageType::Plaintext => {
                        unreachable!("should not be using Double Ratchet for these")
                    }
                }
            }
        }
    }

    // Try some old sessions:
    let mut updated_session = None;

    for (idx, previous) in record.previous_session_states().enumerate() {
        let mut previous = previous?;

        let result = decrypt_message_with_state(
            CurrentOrPrevious::Previous,
            &mut previous,
            ciphertext,
            original_message_type,
            remote_address,
            csprng,
        );

        match result {
            Ok(ptext) => {
                log::info!(
                    "decrypted {:?} message from {} with PREVIOUS session state (base key {})",
                    original_message_type,
                    remote_address,
                    previous
                        .sender_ratchet_key_for_logging()
                        .expect("successful decrypt always has a valid base key"),
                );
                updated_session = Some((ptext, idx, previous));
                break;
            }
            Err(SignalProtocolError::DuplicatedMessage(_, _)) => {
                return result;
            }
            Err(e) => {
                log_decryption_failure(&previous, &e);
                errs.push(e);
            }
        }
    }

    if let Some((ptext, idx, updated_session)) = updated_session {
        record.promote_old_session(idx, updated_session);
        Ok(ptext)
    } else {
        let previous_state_count = || record.previous_session_states().len();

        if let Some(current_state) = record.session_state() {
            log::error!(
                "No valid session for recipient: {}, current session base key {}, number of previous states: {}",
                remote_address,
                current_state.sender_ratchet_key_for_logging()
                .unwrap_or_else(|e| format!("<error: {e}>")),
                previous_state_count(),
            );
        } else {
            log::error!(
                "No valid session for recipient: {}, (no current session state), number of previous states: {}",
                remote_address,
                previous_state_count(),
            );
        }
        log::error!(
            "{}",
            create_decryption_failure_log(remote_address, &errs, record, ciphertext)?
        );
        Err(SignalProtocolError::InvalidMessage(
            original_message_type,
            "decryption failed",
        ))
    }
}

fn decrypt_message_with_record_swoosh(
    remote_address: &ProtocolAddress,
    record: &mut SessionRecord,
    ciphertext: &SignalMessage,
    original_message_type: CiphertextMessageType,
    is_alice: bool,
) -> Result<Vec<u8>> {
    debug_assert!(matches!(
        original_message_type,
        CiphertextMessageType::Whisper | CiphertextMessageType::PreKey
    ));
    let log_decryption_failure = |state: &SessionState, error: &SignalProtocolError| {
        // A warning rather than an error because we try multiple sessions.
        log::warn!(
            "Failed to decrypt {:?} message with ratchet key: {} and counter: {}. \
             Session loaded for {}. Local session has base key: {} and counter: {}. {}",
            original_message_type,
            hex::encode(ciphertext.sender_ratchet_key().unwrap().public_key_bytes()),
            ciphertext.counter(),
            remote_address,
            state
                .sender_ratchet_key_for_logging()
                .unwrap_or_else(|e| format!("<error: {e}>")),
            state.previous_counter(),
            error
        );
    };

    let mut errs = vec![];

    if let Some(current_state) = record.session_state() {
        let mut current_state = current_state.clone();
        
        let result = decrypt_message_with_state_swoosh(
            CurrentOrPrevious::Current,
            &mut current_state,
            ciphertext,
            original_message_type,
            remote_address,
            is_alice,
        );

        match result {
            Ok(ptext) => {
                log::info!(
                    "decrypted {:?} message from {} with current session state (base key {})",
                    original_message_type,
                    remote_address,
                    current_state
                        .sender_ratchet_key_for_logging()
                        .expect("successful decrypt always has a valid base key"),
                );
                record.set_session_state(current_state); // update the state
                return Ok(ptext);
            }
            Err(SignalProtocolError::DuplicatedMessage(_, _)) => {
                return result;
            }
            Err(e) => {
                log_decryption_failure(&current_state, &e);
                errs.push(e);
                match original_message_type {
                    CiphertextMessageType::PreKey => {
                        // A PreKey message creates a session and then decrypts a Whisper message
                        // using that session. No need to check older sessions.
                        log::error!(
                            "{}",
                            create_decryption_failure_log(
                                remote_address,
                                &errs,
                                record,
                                ciphertext
                            )?
                        );
                        // Note that we don't propagate `e` here; we always return InvalidMessage,
                        // as we would for a Whisper message that tried several sessions.
                        return Err(SignalProtocolError::InvalidMessage(
                            original_message_type,
                            "decryption failed",
                        ));
                    }
                    CiphertextMessageType::Whisper => {}
                    CiphertextMessageType::SenderKey | CiphertextMessageType::Plaintext => {
                        unreachable!("should not be using Double Ratchet for these")
                    }
                }
            }
        }
    }

    // Try some old sessions:
    let mut updated_session = None;

    for (idx, previous) in record.previous_session_states().enumerate() {
        let mut previous = previous?;

        let result = decrypt_message_with_state_swoosh(
            CurrentOrPrevious::Previous,
            &mut previous,
            ciphertext,
            original_message_type,
            remote_address,
            is_alice,
        );

        match result {
            Ok(ptext) => {
                log::info!(
                    "decrypted {:?} message from {} with PREVIOUS session state (base key {})",
                    original_message_type,
                    remote_address,
                    previous
                        .sender_ratchet_key_for_logging()
                        .expect("successful decrypt always has a valid base key"),
                );
                updated_session = Some((ptext, idx, previous));
                break;
            }
            Err(SignalProtocolError::DuplicatedMessage(_, _)) => {
                return result;
            }
            Err(e) => {
                log_decryption_failure(&previous, &e);
                errs.push(e);
            }
        }
    }

    if let Some((ptext, idx, updated_session)) = updated_session {
        record.promote_old_session(idx, updated_session);
        Ok(ptext)
    } else {
        let previous_state_count = || record.previous_session_states().len();

        if let Some(current_state) = record.session_state() {
            log::error!(
                "No valid session for recipient: {}, current session base key {}, number of previous states: {}",
                remote_address,
                current_state.sender_ratchet_key_for_logging()
                .unwrap_or_else(|e| format!("<error: {e}>")),
                previous_state_count(),
            );
        } else {
            log::error!(
                "No valid session for recipient: {}, (no current session state), number of previous states: {}",
                remote_address,
                previous_state_count(),
            );
        }
        log::error!(
            "{}",
            create_decryption_failure_log(remote_address, &errs, record, ciphertext)?
        );
        Err(SignalProtocolError::InvalidMessage(
            original_message_type,
            "decryption failed",
        ))
    }
}

#[derive(Clone, Copy)]
enum CurrentOrPrevious {
    Current,
    Previous,
}

impl std::fmt::Display for CurrentOrPrevious {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Current => write!(f, "current"),
            Self::Previous => write!(f, "previous"),
        }
    }
}

fn decrypt_message_with_state<R: Rng + CryptoRng>(
    current_or_previous: CurrentOrPrevious,
    state: &mut SessionState,
    ciphertext: &SignalMessage,
    original_message_type: CiphertextMessageType,
    remote_address: &ProtocolAddress,
    csprng: &mut R,
) -> Result<Vec<u8>> {
    // Check for a completely empty or invalid session state before we do anything else.
    let _ = state.root_key().map_err(|_| {
        SignalProtocolError::InvalidMessage(
            original_message_type,
            "No session available to decrypt",
        )
    })?;

    let ciphertext_version = ciphertext.message_version() as u32;
    if ciphertext_version != state.session_version()? {
        return Err(SignalProtocolError::UnrecognizedMessageVersion(
            ciphertext_version,
        ));
    }

    let their_ephemeral = ciphertext.sender_ratchet_key().unwrap();
    let counter = ciphertext.counter();
    let chain_key = get_or_create_chain_key(state, their_ephemeral, remote_address, csprng)?;
    let message_key_gen = get_or_create_message_key(
        state,
        their_ephemeral,
        remote_address,
        original_message_type,
        &chain_key,
        counter,
    )?;
    let pqr_key = state
        .pq_ratchet_recv(ciphertext.pq_ratchet())
        .map_err(|e| match e {
            spqr::Error::StateDecode => SignalProtocolError::InvalidState(
                "decrypt_message_with_state",
                format!("post-quantum ratchet error: {e}"),
            ),
            _ => {
                log::info!("post-quantum ratchet error in decrypt_message_with_state: {e}");
                SignalProtocolError::InvalidMessage(
                    original_message_type,
                    "post-quantum ratchet error",
                )
            }
        })?;
    let message_keys = message_key_gen.generate_keys(pqr_key);
    /*
    println!("🔑 BOB DECRYPTION KEY (regular) - length: {}, first 8 bytes: {:02x?}", 
             message_keys.cipher_key().len(),
             &message_keys.cipher_key()[..8.min(message_keys.cipher_key().len())]);
    */
    let their_identity_key =
        state
            .remote_identity_key()?
            .ok_or(SignalProtocolError::InvalidSessionStructure(
                "cannot decrypt without remote identity key",
            ))?;

    let mac_valid = ciphertext.verify_mac(
        &their_identity_key,
        &state.local_identity_key()?,
        message_keys.mac_key(),
    )?;

    if !mac_valid {
        return Err(SignalProtocolError::InvalidMessage(
            original_message_type,
            "MAC verification failed",
        ));
    }

    let ptext = match signal_crypto::aes_256_cbc_decrypt(
        ciphertext.body(),
        message_keys.cipher_key(),
        message_keys.iv(),
    ) {
        Ok(ptext) => ptext,
        Err(signal_crypto::DecryptionError::BadKeyOrIv) => {
            log::warn!("{current_or_previous} session state corrupt for {remote_address}",);
            return Err(SignalProtocolError::InvalidSessionStructure(
                "invalid receiver chain message keys",
            ));
        }
        Err(signal_crypto::DecryptionError::BadCiphertext(msg)) => {
            log::warn!("failed to decrypt 1:1 message: {msg}");
            return Err(SignalProtocolError::InvalidMessage(
                original_message_type,
                "failed to decrypt",
            ));
        }
    };

    state.clear_unacknowledged_pre_key_message();

    Ok(ptext)
}

fn decrypt_message_with_state_swoosh(
    current_or_previous: CurrentOrPrevious,
    state: &mut SessionState,
    ciphertext: &SignalMessage,
    original_message_type: CiphertextMessageType,
    remote_address: &ProtocolAddress,
    is_alice: bool,
) -> Result<Vec<u8>> {
    // Check for a completely empty or invalid session state before we do anything else.
    let _ = state.root_key().map_err(|_| {
        SignalProtocolError::InvalidMessage(
            original_message_type,
            "No session available to decrypt",
        )
    })?;

    let ciphertext_version = ciphertext.message_version() as u32;
    if ciphertext_version != state.session_version()? {
        return Err(SignalProtocolError::UnrecognizedMessageVersion(
            ciphertext_version,
        ));
    }

    let their_ephemeral = ciphertext.sender_ratchet_swoosh_key().unwrap();
    let counter = ciphertext.counter();
    
    let chain_key = get_or_create_chain_swoosh_key(state, their_ephemeral, remote_address, is_alice)?;
    let message_key_gen = get_or_create_message_swoosh_key(
        state,
        their_ephemeral,
        remote_address,
        original_message_type,
        &chain_key,
        counter,
    )?;
    let pqr_key = state
        .pq_ratchet_recv(ciphertext.pq_ratchet())
        .map_err(|e| match e {
            spqr::Error::StateDecode => SignalProtocolError::InvalidState(
                "decrypt_message_with_state",
                format!("post-quantum ratchet error: {e}"),
            ),
            _ => {
                log::info!("post-quantum ratchet error in decrypt_message_with_state: {e}");
                SignalProtocolError::InvalidMessage(
                    original_message_type,
                    "post-quantum ratchet error",
                )
            }
        })?;
    let message_keys = message_key_gen.generate_keys(pqr_key);

    // Print Decryption Key - length and first 8 bytes
    /*
    println!("🔑 DECRYPTION KEY - length: {}, first 8 bytes: {:02x?}", 
             message_keys.cipher_key().len(),
             &message_keys.cipher_key()[..8.min(message_keys.cipher_key().len())]);
    */
    let their_identity_key =
        state
            .remote_identity_key()?
            .ok_or(SignalProtocolError::InvalidSessionStructure(
                "cannot decrypt without remote identity key",
            ))?;

    let mac_valid = ciphertext.verify_mac(
        &their_identity_key,
        &state.local_identity_key()?,
        message_keys.mac_key(),
    )?;

    if !mac_valid {
        return Err(SignalProtocolError::InvalidMessage(
            original_message_type,
            "MAC verification failed",
        ));
    }

    let ptext = match signal_crypto::aes_256_cbc_decrypt(
        ciphertext.body(),
        message_keys.cipher_key(),
        message_keys.iv(),
    ) {
        Ok(ptext) => ptext,
        Err(signal_crypto::DecryptionError::BadKeyOrIv) => {
            log::warn!("{current_or_previous} session state corrupt for {remote_address}",);
            return Err(SignalProtocolError::InvalidSessionStructure(
                "invalid receiver chain message keys",
            ));
        }
        Err(signal_crypto::DecryptionError::BadCiphertext(msg)) => {
            log::warn!("failed to decrypt 1:1 message: {msg}");
            return Err(SignalProtocolError::InvalidMessage(
                original_message_type,
                "failed to decrypt",
            ));
        }
    };

    state.clear_unacknowledged_pre_key_message();

    Ok(ptext)
}

fn get_or_create_chain_key<R: Rng + CryptoRng>(
    state: &mut SessionState,
    their_ephemeral: &PublicKey,
    remote_address: &ProtocolAddress,
    csprng: &mut R,
) -> Result<ChainKey> {
    if let Some(chain) = state.get_receiver_chain_key(their_ephemeral)? {
        log::debug!("{remote_address} has existing receiver chain.");
        return Ok(chain);
    }

    log::info!("{remote_address} creating new chains.");

    let root_key = state.root_key()?;
    let our_ephemeral = state.sender_ratchet_private_key()?;
    let receiver_chain = root_key.create_chain(their_ephemeral, &our_ephemeral)?;
    let our_new_ephemeral = KeyPair::generate(csprng);
    let sender_chain = receiver_chain
        .0
        .create_chain(their_ephemeral, &our_new_ephemeral.private_key)?;

    state.set_root_key(&sender_chain.0);
    state.add_receiver_chain(their_ephemeral, &receiver_chain.1);

    let current_index = state.get_sender_chain_key()?.index();
    let previous_index = if current_index > 0 {
        current_index - 1
    } else {
        0
    };
    state.set_previous_counter(previous_index);
    state.set_sender_chain(&our_new_ephemeral, &sender_chain.1);

    Ok(receiver_chain.1)
}

fn get_or_create_chain_swoosh_key(
    state: &mut SessionState,
    their_ephemeral: &PublicSwooshKey,
    remote_address: &ProtocolAddress,
    is_alice: bool,
) -> Result<ChainKey> {
    // First check if we already have an existing receiver chain for this specific key
    if let Some(chain) = state.get_receiver_swoosh_chain_key(their_ephemeral)? {
        log::debug!("{remote_address} has existing receiver chain.");
        return Ok(chain);
    }

    log::info!("{remote_address} creating new chains.");

    let root_key = state.root_key()?;
    let our_ephemeral = state.sender_ratchet_swoosh_private_key()?;
    let our_ephemeral_public = state.sender_ratchet_swoosh_public_key()?;
    let receiver_chain = root_key.create_chain_swoosh(their_ephemeral, &our_ephemeral_public, &our_ephemeral, is_alice)?;
    
    // Debug: Print the first 8 bytes of receiver_chain root key before it gets moved
    //println!("🔑 Receiver swoosh root key first 8 bytes: {:02x?}", &receiver_chain.0.key()[..8]);
    //println!("🔑 Receiver swoosh chain key first 8 bytes: {:02x?}", &receiver_chain.1.key()[..8]);

    let our_new_ephemeral = SwooshKeyPair::generate(is_alice);
    let sender_chain = receiver_chain
        .0
        .create_chain_swoosh(their_ephemeral, &our_new_ephemeral.public_key(), &our_new_ephemeral.private_key(), is_alice)?;

    state.set_root_key(&sender_chain.0);
    state.add_receiver_swoosh_chain(their_ephemeral, &receiver_chain.1);

    let current_index = state.get_sender_chain_key()?.index();
    let previous_index = if current_index > 0 {
        current_index - 1
    } else {
        0
    };
    state.set_previous_counter(previous_index);
    state.set_sender_swoosh_chain(&our_new_ephemeral, &sender_chain.1);

    // Debug: Print the first 8 bytes of sender_chain.1
    //println!("🔑 Sender SWOOSH chain key first 8 bytes: {:02x?}", &sender_chain.1.key()[..8]);

    Ok(receiver_chain.1)
}

fn get_or_create_message_key(
    state: &mut SessionState,
    their_ephemeral: &PublicKey,
    remote_address: &ProtocolAddress,
    original_message_type: CiphertextMessageType,
    chain_key: &ChainKey,
    counter: u32,
) -> Result<MessageKeyGenerator> {
    let chain_index = chain_key.index();

    if chain_index > counter {
        return match state.get_message_keys(their_ephemeral, counter)? {
            Some(keys) => Ok(keys),
            None => {
                log::info!("{remote_address} Duplicate message for counter: {counter}");
                Err(SignalProtocolError::DuplicatedMessage(chain_index, counter))
            }
        };
    }

    assert!(chain_index <= counter);

    let jump = (counter - chain_index) as usize;

    if jump > MAX_FORWARD_JUMPS {
        if state.session_with_self()? {
            log::info!(
                "{remote_address} Jumping ahead {jump} messages (index: {chain_index}, counter: {counter})"
            );
        } else {
            log::error!(
                "{remote_address} Exceeded future message limit: {MAX_FORWARD_JUMPS}, index: {chain_index}, counter: {counter})"
            );
            return Err(SignalProtocolError::InvalidMessage(
                original_message_type,
                "message from too far into the future",
            ));
        }
    }

    let mut chain_key = chain_key.clone();

    while chain_key.index() < counter {
        let message_keys = chain_key.message_keys();
        state.set_message_keys(their_ephemeral, message_keys)?;
        chain_key = chain_key.next_chain_key();
    }

    state.set_receiver_chain_key(their_ephemeral, &chain_key.next_chain_key())?;
    Ok(chain_key.message_keys())
}

fn get_or_create_message_swoosh_key(
    state: &mut SessionState,
    their_ephemeral: &PublicSwooshKey,
    remote_address: &ProtocolAddress,
    original_message_type: CiphertextMessageType,
    chain_key: &ChainKey,
    counter: u32,
) -> Result<MessageKeyGenerator> {
    let chain_index = chain_key.index();

    if chain_index > counter {
        return match state.get_message_swoosh_keys(their_ephemeral, counter)? {
            Some(keys) => Ok(keys),
            None => {
                log::info!("{remote_address} Duplicate message for counter: {counter}");
                Err(SignalProtocolError::DuplicatedMessage(chain_index, counter))
            }
        };
    }

    assert!(chain_index <= counter);

    let jump = (counter - chain_index) as usize;

    if jump > MAX_FORWARD_JUMPS {
        if state.session_with_self()? {
            log::info!(
                "{remote_address} Jumping ahead {jump} messages (index: {chain_index}, counter: {counter})"
            );
        } else {
            log::error!(
                "{remote_address} Exceeded future message limit: {MAX_FORWARD_JUMPS}, index: {chain_index}, counter: {counter})"
            );
            return Err(SignalProtocolError::InvalidMessage(
                original_message_type,
                "message from too far into the future",
            ));
        }
    }

    let mut chain_key = chain_key.clone();

    while chain_key.index() < counter {
        let message_keys = chain_key.message_keys();
        state.set_message_swoosh_keys(their_ephemeral, message_keys)?;
        chain_key = chain_key.next_chain_key();
    }

    state.set_receiver_chain_swoosh_key(their_ephemeral, &chain_key.next_chain_key())?;
    Ok(chain_key.message_keys())
}
