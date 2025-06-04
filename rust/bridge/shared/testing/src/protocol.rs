//
// Copyright 2021-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net::registration::SignedPreKeyBody;
use libsignal_protocol::error::Result;
use libsignal_protocol::*;
use rand::TryRngCore as _;

use crate::*;

bridge_get!(SessionRecord::alice_base_key -> &[u8], ffi = false, node = false);
bridge_get!(
    SessionRecord::get_sender_chain_key_bytes as GetSenderChainKeyValue -> Vec<u8>,
    ffi = false,
    node = false
);
#[bridge_fn(ffi = false, node = false)]
fn SessionRecord_GetReceiverChainKeyValue(
    session_state: &SessionRecord,
    key: &PublicKey,
) -> Result<Option<Vec<u8>>> {
    Ok(session_state
        .get_receiver_chain_key_bytes(key)?
        .map(Vec::from))
}

#[bridge_fn(ffi = false, node = false)]
#[allow(clippy::too_many_arguments)]
fn SessionRecord_InitializeAliceSession(
    identity_key_private: &PrivateKey,
    identity_key_public: &PublicKey,
    base_private: &PrivateKey,
    base_public: &PublicKey,
    their_identity_key: &PublicKey,
    their_signed_prekey: &PublicKey,
    their_ratchet_key: &PublicKey,
    use_pq_ratchet: bool,
) -> Result<Vec<u8>> {
    let our_identity_key_pair = IdentityKeyPair::new(
        IdentityKey::new(*identity_key_public),
        *identity_key_private,
    );

    let our_base_key_pair = KeyPair::new(*base_public, *base_private);

    let their_identity_key = IdentityKey::new(*their_identity_key);

    let mut csprng = rand::rngs::OsRng.unwrap_err();

    let parameters = AliceSignalProtocolParameters::new(
        our_identity_key_pair,
        our_base_key_pair,
        their_identity_key,
        *their_signed_prekey,
        *their_ratchet_key,
        UsePQRatchet::from(use_pq_ratchet),
    );

    initialize_alice_session_record(&parameters, &mut csprng).and_then(|s| s.serialize())
}

#[bridge_fn(ffi = false, node = false)]
#[allow(clippy::too_many_arguments)]
fn SessionRecord_InitializeBobSession(
    identity_key_private: &PrivateKey,
    identity_key_public: &PublicKey,
    signed_prekey_private: &PrivateKey,
    signed_prekey_public: &PublicKey,
    eph_private: &PrivateKey,
    eph_public: &PublicKey,
    their_identity_key: &PublicKey,
    their_base_key: &PublicKey,
    use_pq_ratchet: bool,
) -> Result<Vec<u8>> {
    let our_identity_key_pair = IdentityKeyPair::new(
        IdentityKey::new(*identity_key_public),
        *identity_key_private,
    );

    let our_signed_pre_key_pair = KeyPair::new(*signed_prekey_public, *signed_prekey_private);

    let our_ratchet_key_pair = KeyPair::new(*eph_public, *eph_private);

    let their_identity_key = IdentityKey::new(*their_identity_key);

    let parameters = BobSignalProtocolParameters::new(
        our_identity_key_pair,
        our_signed_pre_key_pair,
        None,
        our_ratchet_key_pair,
        None,
        their_identity_key,
        *their_base_key,
        None,
        UsePQRatchet::from(use_pq_ratchet),
    );

    initialize_bob_session_record(&parameters).and_then(|s| s.serialize())
}

/// cbindgen: ignore
type SignedPublicPreKey = SignedPreKeyBody<Box<[u8]>>;

#[bridge_fn]
fn TESTING_SignedPublicPreKey_CheckBridgesCorrectly(
    source_public_key: &PublicKey,
    signed_pre_key: SignedPublicPreKey,
) {
    let SignedPreKeyBody {
        key_id,
        public_key,
        signature,
    } = signed_pre_key;

    assert_eq!(key_id, 42);
    assert_eq!(
        hex::encode(public_key),
        hex::encode(source_public_key.serialize())
    );
    assert_eq!(&*signature, b"signature");
}
