use crate::{Base64urlUInt, OctetParams, Params as JWKParams, JWK};
use ps_sig::keys::{rsskeygen, PKrss, PKrssError, RSSKeyPair, SKrss, SKrssError};
use thiserror::Error;

pub const OKP_CURVE: &str = "RSSKey2023";

/// Error type for RSS jwk keys.
#[derive(Error, Debug)]
pub enum RSSKeyError {
    #[error("Unrecognised Params varient in JWK, expect OctetParams, found: {0:?}")]
    UnexpectedJWKParamsVarient(Box<JWKParams>),
    #[error("Private key missing from JWK.")]
    MissingPrivateKey,
    #[error("PKrss public key error: {0}")]
    WrappedPKrssError(#[from] PKrssError),
    #[error("SKrss private key error: {0}")]
    WrappedSKrssError(#[from] SKrssError),
}

impl From<&PKrss> for Base64urlUInt {
    fn from(value: &PKrss) -> Self {
        Base64urlUInt(value.to_bytes())
    }
}

impl From<&SKrss> for Base64urlUInt {
    fn from(value: &SKrss) -> Self {
        Base64urlUInt(value.to_bytes())
    }
}

impl TryInto<PKrss> for &Base64urlUInt {
    type Error = RSSKeyError;
    fn try_into(self) -> Result<PKrss, Self::Error> {
        PKrss::from_bytes(&self.0).map_err(|err| err.into())
    }
}

impl TryInto<SKrss> for &Base64urlUInt {
    type Error = RSSKeyError;
    fn try_into(self) -> Result<SKrss, Self::Error> {
        SKrss::from_bytes(&self.0).map_err(|err| err.into())
    }
}

pub fn generate_keys_jwk(
    max_idxs: usize,
    params: &ps_sig::keys::Params,
) -> Result<JWK, crate::error::Error> {
    let (sk, pk) = rsskeygen(max_idxs, params);
    Ok(JWK::from(JWKParams::OKP(OctetParams {
        curve: OKP_CURVE.to_string(),
        public_key: (&pk).into(),
        private_key: Some((&sk).into()),
    })))
}

impl TryInto<RSSKeyPair> for &JWK {
    type Error = RSSKeyError;
    fn try_into(self) -> Result<RSSKeyPair, Self::Error> {
        if let JWKParams::OKP(ref params) = self.params {
            let public_key: PKrss = (&params.public_key).try_into()?;
            let private_key: SKrss = params
                .private_key
                .as_ref()
                .ok_or(RSSKeyError::MissingPrivateKey)?
                .try_into()?;
            Ok(RSSKeyPair {
                public_key,
                private_key,
            })
        } else {
            Err(RSSKeyError::UnexpectedJWKParamsVarient(Box::new(
                self.params.clone(),
            )))
        }
    }
}

impl TryInto<PKrss> for JWK {
    type Error = RSSKeyError;
    fn try_into(self) -> Result<PKrss, Self::Error> {
        if let JWKParams::OKP(params) = self.params {
            Ok((&params.public_key).try_into()?)
        } else {
            Err(RSSKeyError::UnexpectedJWKParamsVarient(Box::new(
                self.params,
            )))
        }
    }
}
