use std::collections::HashMap;

use ps_sig::{
    keys::RSSKeyPair,
    rsssig::{RSVerifyResult, RSignature, RSignatureError},
    FieldElement,
};
use serde_json::Value;
use ssi_dids::did_resolve::{resolve_vm, DIDResolver};
use ssi_json_ld::ContextLoader;
use ssi_jwk::{rss::RSSKeyError, JWK};
use ssi_jws::VerificationWarnings;

use crate::{Error, LinkedDataDocument, LinkedDataProofOptions, Proof, ProofSuiteType};

#[derive(thiserror::Error, Debug)]
pub enum RSSVerificationError {
    #[error("RSS signature error: {0}")]
    WrappedRSignatureError(#[from] RSignatureError),
    #[error("RSS signature verification error: {0}")]
    WrappedRSVerifyResultError(#[from] RSVerifyResult),
}

pub struct RSSSignature2023;
impl RSSSignature2023 {
    pub(crate) async fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
        key: &JWK,
        extra_proof_properties: Option<HashMap<String, Value>>,
    ) -> Result<Proof, Error> {
        // TODO: add proof context?
        let mut proof = Proof::new(ProofSuiteType::RSSSignature2023)
            .with_options(options)
            .with_properties(extra_proof_properties);

        // println!(
        //     "{:?}",
        //     document
        //         .to_dataset_for_signing(None, context_loader)
        //         .await
        //         .unwrap()
        // );
        // println!(
        //     "{}",
        //     serde_json::to_string_pretty(&document.to_value().unwrap()).unwrap()
        // );

        for q in document
            .to_dataset_for_signing(None, context_loader)
            .await
            .unwrap()
            .quads()
        {
            println!("{}", q);
        }

        let msgs = document
            .to_dataset_for_signing(None, context_loader)
            .await?
            .quads()
            .map(|q| FieldElement::from_msg_hash(q.to_string().as_bytes()))
            .collect::<Vec<_>>();

        let rss_keys: RSSKeyPair = key
            .try_into()
            .map_err(|err: RSSKeyError| ssi_jwk::Error::from(err))?;
        let sig = RSignature::new(&msgs, &rss_keys.private_key);
        proof.proof_value = Some(sig.to_hex());
        Ok(proof)
    }

    pub(crate) async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> Result<VerificationWarnings, Error> {
        let sig_hex = proof
            .proof_value
            .as_ref()
            .ok_or(Error::MissingProofSignature)?;
        let verification_method = proof
            .verification_method
            .as_ref()
            .ok_or(Error::MissingVerificationMethod)?;
        let vm = resolve_vm(verification_method, resolver).await?;
        // TODO: update with rss type once appropriate context is available
        if vm.type_ != "Ed25519VerificationKey2018" {
            todo!();
            return Err(Error::VerificationMethodMismatch);
        }
        let jwk = vm.public_key_jwk.ok_or(Error::MissingKey)?;

        let msgs = document
            .to_dataset_for_signing(None, context_loader)
            .await?
            .quads()
            .map(|q| FieldElement::from_msg_hash(q.to_string().as_bytes()))
            .collect::<Vec<_>>();

        let res = RSignature::verifyrsignature(
            &jwk.try_into()
                .map_err(|e: RSSKeyError| <RSSKeyError as Into<ssi_jwk::error::Error>>::into(e))?,
            &RSignature::from_hex(sig_hex)
                .map_err(|e| <RSignatureError as Into<RSSVerificationError>>::into(e))?,
            &msgs,
            &(1..=msgs.len()).collect::<Vec<usize>>(),
        );

        println!("{}", res);

        match res {
            RSVerifyResult::Valid => Ok(vec![]),
            err @ _ => Err(<RSVerifyResult as Into<RSSVerificationError>>::into(err).into()),
        }
    }
}
