use ssi_dids::did_resolve::DIDResolver;
use ssi_jws::VerificationWarnings;

use crate::{Error, LinkedDataDocument, LinkedDataProofOptions, Proof};

pub struct RSSSignature2023;
impl RSSSignature2023 {
    pub(crate) fn sign(
        document: &(dyn LinkedDataDocument + Sync),
        options: &LinkedDataProofOptions,
    ) -> Result<Proof, Error> {
        todo!()
    }
    pub(crate) async fn verify(
        proof: &Proof,
        document: &(dyn LinkedDataDocument + Sync),
        resolver: &dyn DIDResolver,
    ) -> Result<VerificationWarnings, Error> {
        todo!()
    }
}
