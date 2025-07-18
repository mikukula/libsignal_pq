//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;

use prost::Message;

use crate::proto::storage::PreKeyRecordStructure;
use crate::{Result, SignalProtocolError, SwooshPreKeyId};
use pswoosh::keys::{SwooshKeyPair, PrivateSwooshKey, PublicSwooshKey};

/// A unique identifier selecting among this client's known pre-keys.
#[derive(
    Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, derive_more::From, derive_more::Into,
)]
pub struct PreKeyId(u32);

impl fmt::Display for PreKeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct SwooshPreKeyRecordUnsigned {
    pre_key: PreKeyRecordStructure,
}

impl SwooshPreKeyRecordUnsigned {
    pub fn new(id: SwooshPreKeyId, key: &SwooshKeyPair) -> Self {
        let public_key = key.public_key().serialize().to_vec();
        let private_key = key.private_key().serialize();
        Self {
            pre_key: PreKeyRecordStructure {
                id: id.into(),
                public_key,
                private_key,
            },
        }
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        Ok(Self {
            pre_key: PreKeyRecordStructure::decode(data)
                .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?,
        })
    }

    pub fn id(&self) -> Result<PreKeyId> {
        Ok(self.pre_key.id.into())
    }

    pub fn key_pair(&self) -> Result<SwooshKeyPair> {
        Ok(SwooshKeyPair::from_public_and_private(
            &self.pre_key.public_key,
            &self.pre_key.private_key,
        )?)
    }

    pub fn public_key(&self) -> Result<PublicSwooshKey> {
        Ok(PublicSwooshKey::deserialize(&self.pre_key.public_key)?)
    }

    pub fn private_key(&self) -> Result<PrivateSwooshKey> {
        Ok(PrivateSwooshKey::deserialize(&self.pre_key.private_key)?)
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.pre_key.encode_to_vec())
    }
}