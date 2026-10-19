use bitcoin::secp256k1::{self, PublicKey, XOnlyPublicKey};
use bitcoin::sighash::{Annex, EcdsaSighashType, Prevouts, TapSighashType};

use std::sync::LazyLock;

use bitcoin::Script;

use super::*;

static SECP: LazyLock<secp256k1::Secp256k1<secp256k1::All>> = LazyLock::new(secp256k1::Secp256k1::new);

/// Core's IsValidSignatureEncoding: strict DER (BIP66) plus the hashtype byte.
fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    // 0x30 [total-len] 0x02 [R-len] [R] 0x02 [S-len] [S] [hashtype]
    if sig.len() < 9 || sig.len() > 73 || sig[0] != 0x30 || usize::from(sig[1]) != sig.len() - 3 {
        return false;
    }
    let len_r = usize::from(sig[3]);
    if 5 + len_r >= sig.len() {
        return false;
    }
    let len_s = usize::from(sig[5 + len_r]);
    if len_r + len_s + 7 != sig.len() || sig[2] != 0x02 || len_r == 0 || sig[4] & 0x80 != 0 {
        return false;
    }
    // no padding unless the next byte would read as negative
    if len_r > 1 && sig[4] == 0 && sig[5] & 0x80 == 0 {
        return false;
    }
    if sig[len_r + 4] != 0x02 || len_s == 0 || sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    !(len_s > 1 && sig[len_r + 6] == 0 && sig[len_r + 7] & 0x80 == 0)
}

/// Core's CPubKey::CheckLowS on the signature without its hashtype byte.
fn is_low_s(der: &[u8]) -> bool {
    let Ok(sig) = secp256k1::ecdsa::Signature::from_der_lax(der) else { return false };
    let mut norm = sig;
    norm.normalize_s();
    norm == sig
}

impl Exec {
    /// Core's CheckSignatureEncoding (DERSIG, LOW_S, STRICTENC). An empty signature passes.
    pub(crate) fn check_signature_encoding(&self, sig: &[u8]) -> Result<(), ExecError> {
        let Some((&hashtype, der)) = sig.split_last() else { return Ok(()) };
        if (self.opt.verify_dersig || self.opt.verify_low_s || self.opt.verify_strictenc)
            && !is_valid_signature_encoding(sig)
        {
            return Err(ExecError::SigDer);
        }
        if self.opt.verify_low_s && !is_low_s(der) {
            return Err(ExecError::SigHighS);
        }
        // defined: ALL, NONE, SINGLE, each optionally with ANYONECANPAY
        if self.opt.verify_strictenc && !(1..=3).contains(&(hashtype & !0x80)) {
            return Err(ExecError::SigHashtype);
        }
        Ok(())
    }

    /// Core's CheckPubKeyEncoding (STRICTENC, WITNESS_PUBKEYTYPE).
    pub(crate) fn check_pubkey_encoding(&self, pk: &[u8]) -> Result<(), ExecError> {
        let compressed = pk.len() == 33 && matches!(pk[0], 0x02 | 0x03);
        let uncompressed = pk.len() == 65 && pk[0] == 0x04;
        if self.opt.verify_strictenc && !compressed && !uncompressed {
            return Err(ExecError::PubkeyType);
        }
        if self.opt.verify_witness_pubkeytype && self.ctx == ExecCtx::SegwitV0 && !compressed {
            return Err(ExecError::WitnessPubkeyType);
        }
        Ok(())
    }

    pub fn check_sig_ecdsa(&mut self, sig: &[u8], pk: &[u8], script_code: &[u8]) -> bool {
        let pk = match PublicKey::from_slice(pk) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        if sig.is_empty() {
            return false;
        }

        let hashtype = *sig.last().unwrap();
        // as Core's CPubKey::Verify: lax DER (strict DER is the DERSIG flag) and any S (LOW_S is a flag)
        let mut sig = match secp256k1::ecdsa::Signature::from_der_lax(&sig[0..sig.len() - 1]) {
            Ok(s) => s,
            Err(_) => return false,
        };
        sig.normalize_s();

        let sighash = if self.ctx == ExecCtx::SegwitV0 {
            self.sighashcache
                .p2wsh_signature_hash(
                    self.tx.input_idx,
                    Script::from_bytes(script_code),
                    self.tx.prevouts[self.tx.input_idx].value,
                    //TODO(stevenroose) this might not actually emulate consensus behavior
                    EcdsaSighashType::from_consensus(hashtype as u32),
                )
                .expect("only happens on prevout index out of bounds")
                .into()
        } else if self.ctx == ExecCtx::Legacy {
            self.sighashcache
                .legacy_signature_hash(
                    self.tx.input_idx,
                    Script::from_bytes(&without_codeseparators(script_code)),
                    hashtype as u32,
                )
                .expect("TODO(stevenroose) seems to only happen if prevout index out of bound")
                .into()
        } else {
            unreachable!();
        };

        SECP.verify_ecdsa(&sighash, &sig, &pk).is_ok()
    }

    /// [pk] should be passed as 32-bytes.
    pub fn check_sig_schnorr(&mut self, sig: &[u8], pk: &[u8]) -> Result<(), ExecError> {
        assert_eq!(pk.len(), 32);

        if sig.len() != 64 && sig.len() != 65 {
            return Err(ExecError::SchnorrSigSize);
        }

        let pk = XOnlyPublicKey::from_slice(pk).expect("TODO(stevenroose) what to do here?");
        let (sig, hashtype) = if sig.len() == 65 {
            let b = *sig.last().unwrap();
            let sig = secp256k1::schnorr::Signature::from_slice(&sig[0..sig.len() - 1])
                .map_err(|_| ExecError::SchnorrSig)?;

            if b == TapSighashType::Default as u8 {
                return Err(ExecError::SchnorrSigHashtype);
            }
            //TODO(stevenroose) core does not error here
            let sht =
                TapSighashType::from_consensus_u8(b).map_err(|_| ExecError::SchnorrSigHashtype)?;
            (sig, sht)
        } else {
            let sig = secp256k1::schnorr::Signature::from_slice(sig)
                .map_err(|_| ExecError::SchnorrSig)?;
            (sig, TapSighashType::Default)
        };

        let (leaf_hash, annex) = self.tx.taproot_annex_scriptleaf.as_ref().unwrap();
        let sighash = self
            .sighashcache
            .taproot_signature_hash(
                self.tx.input_idx,
                &Prevouts::All(&self.tx.prevouts),
                annex
                    .as_ref()
                    .map(|a| Annex::new(a).expect("we checked annex prefix before")),
                Some((*leaf_hash, self.last_codeseparator_pos.unwrap_or(u32::MAX))),
                hashtype,
            )
            .expect("TODO(stevenroose) seems to only happen if prevout index out of bound");

        if SECP.verify_schnorr(&sig, &sighash.into(), &pk) != Ok(()) {
            return Err(ExecError::SchnorrSig);
        }

        Ok(())
    }
}
