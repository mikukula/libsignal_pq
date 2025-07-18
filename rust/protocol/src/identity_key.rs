//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Wrappers over cryptographic primitives from [`libsignal_core::curve`] to represent a user.

#![warn(missing_docs)]

use prost::Message;
use pswoosh::keys::{PrivateSwooshKey, PublicSwooshKey, SwooshKeyPair};
use rand::{CryptoRng, Rng};

use crate::{proto, KeyPair, PrivateKey, PublicKey, Result, SignalProtocolError};

// Used for domain separation between alternate-identity signatures and other key-to-key signatures.
const ALTERNATE_IDENTITY_SIGNATURE_PREFIX_1: &[u8] = &[0xFF; 32];
const ALTERNATE_IDENTITY_SIGNATURE_PREFIX_2: &[u8] = b"Signal_PNI_Signature";

/// A public key that represents the identity of a user.
///
/// Wrapper for [`PublicKey`].
#[derive(
    Debug, PartialOrd, Ord, PartialEq, Eq, Clone, Copy, derive_more::From, derive_more::Into,
)]
pub struct IdentityKey {
    public_key: PublicKey,
}

impl IdentityKey {
    /// Initialize a public-facing identity from a public key.
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    /// Return the public key representing this identity.
    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Return an owned byte slice which can be deserialized with [`Self::decode`].
    #[inline]
    pub fn serialize(&self) -> Box<[u8]> {
        self.public_key.serialize()
    }

    /// Deserialize a public identity from a byte slice.
    pub fn decode(value: &[u8]) -> Result<Self> {
        let pk = PublicKey::try_from(value)?;
        Ok(Self { public_key: pk })
    }

    /// Given a trusted identity `self`, verify that `other` represents an alternate identity for
    /// this user.
    ///
    /// `signature` must be calculated from [`IdentityKeyPair::sign_alternate_identity`].
    pub fn verify_alternate_identity(&self, other: &IdentityKey, signature: &[u8]) -> Result<bool> {
        Ok(self.public_key.verify_signature_for_multipart_message(
            &[
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_1,
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_2,
                &other.serialize(),
            ],
            signature,
        ))
    }
}

impl TryFrom<&[u8]> for IdentityKey {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        IdentityKey::decode(value)
    }
}

/// The private identity of a user.
///
/// Can be converted to and from [`KeyPair`].
#[derive(Copy, Clone)]
pub struct IdentityKeyPair {
    identity_key: IdentityKey,
    private_key: PrivateKey,
    public_swoosh_key: Option<PublicSwooshKey>,
    private_swoosh_key: Option<PrivateSwooshKey>,
}

impl IdentityKeyPair {
    /// Create a key pair from a public `identity_key` and a private `private_key`.
    pub fn new(identity_key: IdentityKey, private_key: PrivateKey) -> Self {
        Self {
            identity_key,
            private_key,
            public_swoosh_key: None,
            private_swoosh_key: None,
        }
    }

    /// Generate a random new identity from randomness in `csprng`.
    pub fn generate<R: CryptoRng + Rng>(csprng: &mut R) -> Self {
        let keypair = KeyPair::generate(csprng);

        Self {
            identity_key: keypair.public_key.into(),
            private_key: keypair.private_key,
            public_swoosh_key: None,
            private_swoosh_key: None,
        }
    }

    /// Generate a random new identity with Swoosh keys from randomness in `csprng`.
    pub fn generate_with_swoosh<R: CryptoRng + Rng>(csprng: &mut R, is_alice: bool) -> Self {
        let keypair = KeyPair::generate(csprng);
        let swoosh_key_pair = SwooshKeyPair::generate(is_alice);
        Self {
            identity_key: keypair.public_key.into(),
            private_key: keypair.private_key,
            public_swoosh_key: Some(swoosh_key_pair.public_key),
            private_swoosh_key: Some(swoosh_key_pair.private_key),
        }
    }

    /// Return the public identity of this user.
    #[inline]
    pub fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    /// Return the public key that defines this identity.
    #[inline]
    pub fn public_key(&self) -> &PublicKey {
        self.identity_key.public_key()
    }

    /// Return the private key that defines this identity.
    #[inline]
    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Return the public Swoosh key that defines this identity.
    #[inline]
    pub fn public_swoosh_key(&self) -> Option<&PublicSwooshKey> {
        self.public_swoosh_key.as_ref()
    }

    /// Return the private Swoosh key that defines this identity.
    #[inline]
    pub fn private_swoosh_key(&self) -> Option<&PrivateSwooshKey> {
        self.private_swoosh_key.as_ref()
    }

    /// Return a byte slice which can later be deserialized with [`Self::try_from`].
    pub fn serialize(&self) -> Box<[u8]> {
        let structure = proto::storage::IdentityKeyPairStructure {
            public_key: self.identity_key.serialize().to_vec(),
            private_key: self.private_key.serialize().to_vec(),
            public_swoosh_identity_key: self
                .public_swoosh_key
                .as_ref()
                .map(|k| k.serialize().to_vec())
                .unwrap_or_default(),
            private_swoosh_identity_key: self
                .private_swoosh_key
                .as_ref()
                .map(|k| k.serialize())
                .unwrap_or_default(),
        };

        let result = structure.encode_to_vec();
        result.into_boxed_slice()
    }

    /// Generate a signature claiming that `other` represents the same user as `self`.
    pub fn sign_alternate_identity<R: Rng + CryptoRng>(
        &self,
        other: &IdentityKey,
        rng: &mut R,
    ) -> Result<Box<[u8]>> {
        Ok(self.private_key.calculate_signature_for_multipart_message(
            &[
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_1,
                ALTERNATE_IDENTITY_SIGNATURE_PREFIX_2,
                &other.serialize(),
            ],
            rng,
        )?)
    }
}

impl TryFrom<&[u8]> for IdentityKeyPair {
    type Error = SignalProtocolError;

    fn try_from(value: &[u8]) -> Result<Self> {
        let structure = proto::storage::IdentityKeyPairStructure::decode(value)
            .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?;
        Ok(Self {
            identity_key: IdentityKey::try_from(&structure.public_key[..])?,
            private_key: PrivateKey::deserialize(&structure.private_key)?,
            public_swoosh_key: PublicSwooshKey::deserialize(
                &structure.public_swoosh_identity_key,
            )
            .ok(),
            private_swoosh_key: PrivateSwooshKey::deserialize(
                &structure.private_swoosh_identity_key,
            )
            .ok(),
        })
    }
}

impl TryFrom<PrivateKey> for IdentityKeyPair {
    type Error = SignalProtocolError;

    fn try_from(private_key: PrivateKey) -> Result<Self> {
        let identity_key = IdentityKey::new(private_key.public_key()?);
        Ok(Self::new(identity_key, private_key))
    }
}

impl From<KeyPair> for IdentityKeyPair {
    fn from(value: KeyPair) -> Self {
        Self {
            identity_key: value.public_key.into(),
            private_key: value.private_key,
            public_swoosh_key: None,
            private_swoosh_key: None,
        }
    }
}

impl From<IdentityKeyPair> for KeyPair {
    fn from(value: IdentityKeyPair) -> Self {
        Self::new(value.identity_key.into(), value.private_key)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use rand::TryRngCore as _;

    use super::*;

    #[test]
    fn test_identity_key_from() {
        let key_pair = KeyPair::generate(&mut OsRng.unwrap_err());
        let key_pair_public_serialized = key_pair.public_key.serialize();
        let identity_key = IdentityKey::from(key_pair.public_key);
        assert_eq!(key_pair_public_serialized, identity_key.serialize());
    }

    #[test]
    fn test_serialize_identity_key_pair() -> Result<()> {
        let identity_key_pair = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
        let serialized = identity_key_pair.serialize();
        let deserialized_identity_key_pair = IdentityKeyPair::try_from(&serialized[..])?;
        assert_eq!(
            identity_key_pair.identity_key(),
            deserialized_identity_key_pair.identity_key()
        );
        assert_eq!(
            identity_key_pair.private_key().key_type(),
            deserialized_identity_key_pair.private_key().key_type()
        );
        assert_eq!(
            identity_key_pair.private_key().serialize(),
            deserialized_identity_key_pair.private_key().serialize()
        );

        Ok(())
    }

    #[test]
    fn test_alternate_identity_signing() -> Result<()> {
        let mut rng = OsRng.unwrap_err();
        let primary = IdentityKeyPair::generate(&mut rng);
        let secondary = IdentityKeyPair::generate(&mut rng);

        let signature = secondary.sign_alternate_identity(primary.identity_key(), &mut rng)?;
        assert!(secondary
            .identity_key()
            .verify_alternate_identity(primary.identity_key(), &signature)?);
        // Not symmetric.
        assert!(!primary
            .identity_key()
            .verify_alternate_identity(secondary.identity_key(), &signature)?);

        let another_signature =
            secondary.sign_alternate_identity(primary.identity_key(), &mut rng)?;
        assert_ne!(signature, another_signature);
        assert!(secondary
            .identity_key()
            .verify_alternate_identity(primary.identity_key(), &another_signature)?);

        let unrelated = IdentityKeyPair::generate(&mut rng);
        assert!(!secondary
            .identity_key()
            .verify_alternate_identity(unrelated.identity_key(), &signature)?);
        assert!(!unrelated
            .identity_key()
            .verify_alternate_identity(primary.identity_key(), &signature)?);

        Ok(())
    }
}
