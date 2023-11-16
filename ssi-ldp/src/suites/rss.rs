use grdf::HashDataset;
use iref::IriBuf;
use ps_sig::{
    keys::RSSKeyPair,
    rsssig::{RSVerifyResult, RSignature, RSignatureError},
    FieldElement,
};
use rdf_types::{Subject, Term};
use serde_json::Value;
use ssi_dids::did_resolve::{resolve_vm, DIDResolver};
use ssi_json_ld::{json_to_dataset, ContextLoader};
use ssi_jwk::{rss::RSSKeyError, JWK};
use ssi_jws::VerificationWarnings;
use std::collections::{HashMap, HashSet};

use crate::{Error, LinkedDataDocument, LinkedDataProofOptions, Proof, ProofSuiteType};

#[derive(thiserror::Error, Debug)]
pub enum RSSError {
    #[error("Information in selective disclosure mask is inconsistent with information in the original document: {0}")]
    InconsistentValuesInMask(String),
    #[error("Keys in selective disclosure mask map are mismatched with keys in document.")]
    MaskKeyMismatch,
    #[error("Invalid proof type. Expected RSSSignature2023, found: {0:?}")]
    InvalidProofType(ProofSuiteType),
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

        let msgs = document
            .to_dataset_for_signing(None, context_loader)
            .await?
            .quads()
            .map(|q| FieldElement::from_msg_hash(q.to_string().as_bytes()))
            .collect::<Vec<_>>();
        println!("{:?}", msgs.len());

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
        if vm.type_ != "JsonWebSignature2020" {
            todo!("checking vm type, found: {}", vm.type_);
            return Err(Error::VerificationMethodMismatch);
        }
        let jwk = vm.public_key_jwk.ok_or(Error::MissingKey)?;

        let InferredDataset {
            null_marked_dataset,
            inferred_idxs,
        } = infer_disclosed_idxs(document, context_loader).await?;

        println!("{:?}", inferred_idxs);

        let msgs = null_marked_dataset
            .quads()
            .enumerate()
            .map(|(i, q)| {
                if inferred_idxs.contains(&(i + 1)) {
                    FieldElement::from_msg_hash(q.to_string().as_bytes())
                } else {
                    FieldElement::zero()
                }
            })
            .collect::<Vec<_>>();

        let res = RSignature::verifyrsignature(
            &jwk.try_into()
                .map_err(|e: RSSKeyError| <RSSKeyError as Into<ssi_jwk::error::Error>>::into(e))?,
            &RSignature::from_hex(sig_hex)
                .map_err(|e| <RSignatureError as Into<RSSError>>::into(e))?,
            &msgs,
            &inferred_idxs,
        );

        match res {
            RSVerifyResult::Valid => Ok(vec![]),
            err @ _ => Err(<RSVerifyResult as Into<RSSError>>::into(err).into()),
        }
    }
}

pub struct InferredDataset {
    pub inferred_idxs: Vec<usize>,
    pub null_marked_dataset: HashDataset<Subject, IriBuf, Term>,
}

const NULL_MARKER: &str = "__12345__";
pub async fn infer_disclosed_idxs(
    document: &(dyn LinkedDataDocument + Sync),
    context_loader: &mut ContextLoader,
) -> Result<InferredDataset, Error> {
    let dataset_disclosed = document
        .to_dataset_for_signing(None, context_loader)
        .await?;

    let disclosed_set =
        &dataset_disclosed
            .quads()
            .map(|q| q.to_string())
            .fold(HashSet::new(), |mut set, q| {
                set.insert(q);
                set
            });

    // Mark null values in a json Value
    fn mark_null(val: Value, null_marker: &str) -> Value {
        match val {
            Value::Null => Value::String(null_marker.to_string()),
            Value::Object(mut map) => {
                // TODO: this is specific to credentials, and this crate should generalise above them
                if map.contains_key("proof") {
                    map.remove("proof").unwrap();
                }
                Value::Object(
                    map.into_iter()
                        .map(|(k, v)| (k, mark_null(v, NULL_MARKER)))
                        .collect(),
                )
            }
            // TODO: Arrays are not handled here, throw Err if encountered?
            val @ _ => val,
        }
    }

    let doc_value_map = document.to_value().unwrap();
    let null_marked_map = mark_null(doc_value_map.clone(), NULL_MARKER);
    // Convert null_marked map to rdf quads
    let json = ssi_json_ld::syntax::to_value_with(null_marked_map, Default::default).unwrap();
    let null_marked_dataset = json_to_dataset(json, context_loader, None).await.unwrap();

    // print for debugging only
    for q in dataset_disclosed.quads() {
        println!("{}", q);
    }
    println!("\n\n");
    for q in null_marked_dataset.quads() {
        println!("{}", q);
    }

    // Test each of quads_full for membership of disclosed_set
    let inferred_idxs = null_marked_dataset
        .quads()
        .enumerate()
        .filter_map(|(i, q)| {
            if disclosed_set.contains(&q.to_string()) {
                // RSS uses 1-indexing
                Some(i + 1)
            } else {
                None
            }
        })
        .collect::<Vec<usize>>();

    Ok(InferredDataset {
        inferred_idxs,
        null_marked_dataset,
    })
}
