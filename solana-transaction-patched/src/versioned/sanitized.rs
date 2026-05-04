use {
    crate::versioned::{FalconSigner, VersionedTransaction},
    solana_message::SanitizedVersionedMessage,
    solana_sanitize::SanitizeError,
    solana_signature::Signature,
};

/// Wraps a sanitized `VersionedTransaction` to provide a safe API
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SanitizedVersionedTransaction {
    /// List of signatures
    pub(crate) signatures: Vec<Signature>,
    /// Message to sign.
    pub(crate) message: SanitizedVersionedMessage,
    /// PQC Falcon-512 signer data (propagated from VersionedTransaction).
    pub(crate) falcon_signer: Option<FalconSigner>,
}

impl TryFrom<VersionedTransaction> for SanitizedVersionedTransaction {
    type Error = SanitizeError;
    fn try_from(tx: VersionedTransaction) -> Result<Self, Self::Error> {
        Self::try_new(tx)
    }
}

impl SanitizedVersionedTransaction {
    pub fn try_new(tx: VersionedTransaction) -> Result<Self, SanitizeError> {
        tx.sanitize_signatures()?;
        Ok(Self {
            signatures: tx.signatures,
            message: SanitizedVersionedMessage::try_from(tx.message)?,
            falcon_signer: tx.falcon_signer,
        })
    }

    pub fn get_message(&self) -> &SanitizedVersionedMessage {
        &self.message
    }

    /// Consumes the SanitizedVersionedTransaction, returning the fields individually.
    pub fn destruct(self) -> (Vec<Signature>, SanitizedVersionedMessage, Option<FalconSigner>) {
        (self.signatures, self.message, self.falcon_signer)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        solana_hash::Hash,
        solana_message::{v0, VersionedMessage},
        solana_pubkey::Pubkey,
    };

    #[test]
    fn test_try_new_with_invalid_signatures() {
        let tx = VersionedTransaction {
            signatures: vec![],
            message: VersionedMessage::V0(
                v0::Message::try_compile(&Pubkey::new_unique(), &[], &[], Hash::default()).unwrap(),
            ),
            falcon_signer: None,
        };

        assert_eq!(
            SanitizedVersionedTransaction::try_new(tx),
            Err(SanitizeError::IndexOutOfBounds)
        );
    }

    #[test]
    fn test_try_new() {
        let mut message =
            v0::Message::try_compile(&Pubkey::new_unique(), &[], &[], Hash::default()).unwrap();
        message.header.num_readonly_signed_accounts += 1;

        let tx = VersionedTransaction {
            signatures: vec![Signature::default()],
            message: VersionedMessage::V0(message),
            falcon_signer: None,
        };

        assert_eq!(
            SanitizedVersionedTransaction::try_new(tx),
            Err(SanitizeError::InvalidValue)
        );
    }
}
