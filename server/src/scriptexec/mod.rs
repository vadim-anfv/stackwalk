//! Vendored from https://github.com/BitVM/rust-bitcoin-scriptexec (rev ba96bc2bd7),
//! license CC0-1.0. Local changes: stack entries carry ids (moves keep them, copies
//! get new ones), OP_CHECKMULTISIG(VERIFY) implemented, NULLFAIL / NULLDUMMY added,
//! FindAndDelete bounds fixed, signature checks recorded for notes, opcode count exposed,
//! wasm/json/cli dropped. As in Core: PICK / ROLL pop n before checking it, CSV masks its
//! operand, MINIMALDATA only on executed pushes, OP_RESERVED fails only when executed, the
//! script code starts after OP_CODESEPARATOR, OP_CAT is disabled (the experimental OP_CAT
//! is gone). Execution stats and other unused API removed. Checked against Core's
//! script_tests.json (src/core_vectors.rs), which led to: ECDSA signatures parsed lax DER with
//! S normalized, as Core verifies them; WITNESS_PUBKEYTYPE an option, checked as Core does
//! (compressed = 33 bytes with an 02 / 03 prefix, not just "not 65 bytes"); DERSIG, LOW_S and
//! STRICTENC added (Core's CheckSignatureEncoding / CheckPubKeyEncoding); the 10000-byte script
//! size limit; DISCOURAGE_UPGRADABLE_NOPS.

use std::borrow::Cow;

use bitcoin::consensus::Encodable;
use bitcoin::opcodes::{Opcode, all::*};
use bitcoin::script::{self, Instruction, Instructions, Script, ScriptBuf};
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::{self, TapLeafHash};
use bitcoin::transaction::{self, Transaction, TxOut};

mod ops;

mod utils;
use utils::ConditionStack;

mod signatures;

mod error;
pub use error::{Error, ExecError};

pub mod parse;
pub use parse::parse_opcode;

mod stack;
pub use stack::{Entry, IdGen, Stack, scriptint_vec};

/// Maximum number of non-push operations per script
const MAX_OPS_PER_SCRIPT: usize = 201;

/// Maximum number of bytes pushable to the stack
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum script size in bytes (legacy and segwit v0)
const MAX_SCRIPT_SIZE: usize = 10_000;

/// Maximum number of values on script interpreter stack
const MAX_STACK_SIZE: usize = 1000;

/// If this flag is set, CTxIn::nSequence is NOT interpreted as a
/// relative lock-time.
/// It skips SequenceLocks() for any input that has it set (BIP 68).
/// It fails OP_CHECKSEQUENCEVERIFY/CheckSequence() for any input that has
/// it set (BIP 112).
const SEQUENCE_LOCKTIME_DISABLE_FLAG: u32 = 1 << 31;

/// How much weight budget is added to the witness size (Tapscript only, see BIP 342).
const VALIDATION_WEIGHT_OFFSET: i64 = 50;

/// Validation weight per passing signature (Tapscript only, see BIP 342).
const VALIDATION_WEIGHT_PER_SIGOP_PASSED: i64 = 50;

// Maximum number of public keys per multisig
const MAX_PUBKEYS_PER_MULTISIG: i64 = 20;

/// Used to fine-tune different variables during execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// Require data pushes be minimally encoded.
    pub require_minimal: bool, //TODO(stevenroose) double check all fRequireMinimal usage in Core
    /// Verify OP_CHECKLOCKTIMEVERIFY.
    pub verify_cltv: bool,
    /// Verify OP_CHECKSEQUENCEVERIFY.
    pub verify_csv: bool,
    /// Verify conditionals are minimally encoded.
    pub verify_minimal_if: bool,
    /// Enfore a strict limit of 1000 total stack items.
    pub enforce_stack_limit: bool,
    /// A failing signature check must have an empty signature (BIP146 NULLFAIL, policy).
    pub verify_nullfail: bool,
    /// The CHECKMULTISIG dummy element must be empty (BIP147 NULLDUMMY).
    pub verify_nulldummy: bool,
    /// Segwit v0 public keys must be compressed (WITNESS_PUBKEYTYPE, policy).
    pub verify_witness_pubkeytype: bool,
    /// Signatures must be strict DER (BIP66 DERSIG).
    pub verify_dersig: bool,
    /// Signatures must have a low S (LOW_S, policy).
    pub verify_low_s: bool,
    /// Defined hashtypes, well-formed public keys, strict DER (STRICTENC, policy).
    pub verify_strictenc: bool,
    /// OP_NOP1, OP_NOP4..OP_NOP10 fail (DISCOURAGE_UPGRADABLE_NOPS, policy).
    pub verify_discourage_upgradable_nops: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            require_minimal: true,
            verify_cltv: true,
            verify_csv: true,
            verify_minimal_if: true,
            enforce_stack_limit: true,
            verify_nullfail: true,
            verify_nulldummy: true,
            verify_witness_pubkeytype: true,
            verify_dersig: true,
            verify_low_s: true,
            verify_strictenc: true,
            verify_discourage_upgradable_nops: true,
        }
    }
}

/// One signature check performed by the last executed opcode: (sig, pubkey, valid).
#[derive(Debug, Clone)]
pub struct SigCheck {
    pub sig: Vec<u8>,
    pub pk: Vec<u8>,
    pub ok: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecCtx {
    Legacy,
    SegwitV0,
    Tapscript,
}

pub struct TxTemplate {
    pub tx: Transaction,
    pub prevouts: Vec<TxOut>,
    pub input_idx: usize,
    pub taproot_annex_scriptleaf: Option<(TapLeafHash, Option<Vec<u8>>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub success: bool,
    pub error: Option<ExecError>,
    pub opcode: Option<Opcode>,
    pub final_stack: Stack,
}

impl ExecutionResult {
    fn from_final_stack(ctx: ExecCtx, final_stack: Stack) -> ExecutionResult {
        ExecutionResult {
            success: match ctx {
                ExecCtx::Legacy => {
                    if final_stack.is_empty() {
                        false
                    } else {
                        script::read_scriptbool(&final_stack.last().unwrap())
                    }
                }
                ExecCtx::SegwitV0 | ExecCtx::Tapscript => {
                    if final_stack.len() != 1 {
                        false
                    } else {
                        script::read_scriptbool(&final_stack.last().unwrap())
                    }
                }
            },
            final_stack,
            error: None,
            opcode: None,
        }
    }
}

/// Partial execution of a script.
pub struct Exec {
    ctx: ExecCtx,
    opt: Options,
    tx: TxTemplate,
    result: Option<ExecutionResult>,

    sighashcache: SighashCache<Transaction>,
    script: &'static Script,
    instructions: Instructions<'static>,
    current_position: usize,
    cond_stack: ConditionStack,
    stack: Stack,
    altstack: Stack,
    last_codeseparator_pos: Option<u32>,
    // Initially set to the whole script, but updated when
    // OP_CODESEPARATOR is encountered.
    script_code: &'static Script,

    opcode_count: usize,
    validation_weight: i64,

    /// Signature checks done by the last executed opcode.
    pub last_checks: Vec<SigCheck>,
}

impl std::ops::Drop for Exec {
    fn drop(&mut self) {
        // we need to safely drop the script we allocated
        unsafe {
            let script = core::mem::replace(&mut self.script, Script::from_bytes(&[]));
            let _ = Box::from_raw(script as *const Script as *mut Script);
        }
    }
}

impl Exec {
    pub fn new(
        ctx: ExecCtx,
        opt: Options,
        tx: TxTemplate,
        script: ScriptBuf,
        stack: Stack,
    ) -> Result<Exec, Error> {
        let script_witness = stack.as_v8_vec();
        if ctx == ExecCtx::Tapscript {
            if tx.taproot_annex_scriptleaf.is_none() {
                return Err(Error::Other("missing taproot tx info in tapscript context"));
            }

            if let Some((_, Some(ref annex))) = tx.taproot_annex_scriptleaf
                && annex.first() != Some(&taproot::TAPROOT_ANNEX_PREFIX)
            {
                return Err(Error::Other("invalid annex: missing prefix"));
            }
        }

        // as Core: the size limit comes first, even for a script that does not parse
        let too_big = ctx != ExecCtx::Tapscript && script.len() > MAX_SCRIPT_SIZE;

        // We want to make sure the script is valid so we don't have to throw parsing errors
        // while executing. Minimal pushes are checked as they run, as Core does (MINIMALDATA
        // applies to executed pushes only).
        let instructions = script.instructions();
        if !too_big && let Some(err) = instructions.clone().find_map(|res| res.err()) {
            return Err(Error::InvalidScript(err));
        }

        // *****
        // Make sure there is no more possible exit path after this point!
        // Otherwise we are leaking memory.
        // *****

        // We box alocate the script to get a static Instructions iterator.
        // We will manually drop this allocation in the ops::Drop impl.
        let script = Box::leak(script.into_boxed_script()) as &'static Script;
        let instructions = script.instructions();

        //TODO(stevenroose) make this more efficient
        let witness_size =
            Encodable::consensus_encode(&script_witness, &mut bitcoin::io::sink()).unwrap();
        let validation_weight = VALIDATION_WEIGHT_OFFSET + witness_size as i64;

        let mut exec = Exec {
            ctx,
            result: None,

            sighashcache: SighashCache::new(tx.tx.clone()),
            script,
            instructions,
            current_position: 0,
            cond_stack: ConditionStack::new(),
            altstack: Stack::new(stack.ids()),
            stack,
            last_checks: Vec::new(),
            opcode_count: 0,
            validation_weight,
            last_codeseparator_pos: None,
            script_code: script,

            opt,
            tx,
        };
        if too_big {
            // the first step reports it, before any instruction is read
            let _ = exec.fail(ExecError::ScriptSize);
        }
        Ok(exec)
    }

    //////////////////
    // SOME GETTERS //
    //////////////////

    pub fn script_position(&self) -> usize {
        self.script.len() - self.instructions.as_script().len()
    }

    pub fn stack(&self) -> &Stack {
        &self.stack
    }

    pub fn altstack(&self) -> &Stack {
        &self.altstack
    }

    /// Opcodes counted so far (stackwalk): also after a failure.
    pub fn opcode_count(&self) -> usize {
        self.opcode_count
    }

    pub fn cond_stack(&self) -> &ConditionStack {
        &self.cond_stack
    }

    ///////////////
    // UTILITIES //
    ///////////////

    fn fail(&mut self, err: ExecError) -> Result<(), &ExecutionResult> {
        let res = ExecutionResult {
            success: false,
            error: Some(err),
            opcode: None,
            final_stack: self.stack.clone(),
        };
        self.result = Some(res);
        Err(self.result.as_ref().unwrap())
    }

    fn failop(&mut self, err: ExecError, op: Opcode) -> Result<(), &ExecutionResult> {
        let res = ExecutionResult {
            success: false,
            error: Some(err),
            opcode: Some(op),
            final_stack: self.stack.clone(),
        };
        self.result = Some(res);
        Err(self.result.as_ref().unwrap())
    }

    fn check_lock_time(&mut self, lock_time: i64) -> bool {
        use bitcoin::locktime::absolute::LockTime;
        let lock_time = match lock_time.try_into() {
            Ok(l) => LockTime::from_consensus(l),
            Err(_) => return false,
        };

        match (lock_time, self.tx.tx.lock_time) {
            (LockTime::Blocks(h1), LockTime::Blocks(h2)) if h1 > h2 => return false,
            (LockTime::Seconds(t1), LockTime::Seconds(t2)) if t1 > t2 => return false,
            (LockTime::Blocks(_), LockTime::Seconds(_)) => return false,
            (LockTime::Seconds(_), LockTime::Blocks(_)) => return false,
            _ => {}
        }

        if self.tx.tx.input[self.tx.input_idx].sequence.is_final() {
            return false;
        }

        true
    }

    fn check_sequence(&mut self, sequence: i64) -> bool {
        use bitcoin::locktime::relative::LockTime;

        // Fail if the transaction's version number is not set high
        // enough to trigger BIP 68 rules.
        if self.tx.tx.version < transaction::Version::TWO {
            return false;
        }

        let input_sequence = self.tx.tx.input[self.tx.input_idx].sequence;
        let input_lock_time = match input_sequence.to_relative_lock_time() {
            Some(lt) => lt,
            None => return false,
        };

        // as Core: only the type flag and the value count (a 5-byte operand can exceed u32)
        let lock_time =
            match LockTime::from_consensus((sequence & 0x0040_ffff) as u32) {
                Ok(lt) => lt,
                Err(_) => return false,
            };

        match (lock_time, input_lock_time) {
            (LockTime::Blocks(h1), LockTime::Blocks(h2)) if h1 > h2 => return false,
            (LockTime::Time(t1), LockTime::Time(t2)) if t1 > t2 => return false,
            (LockTime::Blocks(_), LockTime::Time(_)) => return false,
            (LockTime::Time(_), LockTime::Blocks(_)) => return false,
            _ => {}
        }

        true
    }

    /// Script code with the given signatures removed (legacy FindAndDelete).
    /// Note: removes raw signature bytes, Core removes the push-encoded signature.
    pub(crate) fn script_code_without(&self, sigs: &[Vec<u8>]) -> Vec<u8> {
        let mut scriptcode = Cow::Borrowed(self.script_code.as_bytes());
        if self.ctx == ExecCtx::Legacy {
            for sig in sigs {
                if sig.is_empty() {
                    continue;
                }
                let mut i = 0;
                while i + sig.len() <= scriptcode.len() {
                    if &scriptcode[i..i + sig.len()] == sig.as_slice() {
                        scriptcode.to_mut().drain(i..i + sig.len());
                    } else {
                        i += 1;
                    }
                }
            }
        }
        scriptcode.into_owned()
    }

    pub(crate) fn check_sig_with_code(
        &mut self,
        sig: &[u8],
        pk: &[u8],
        scriptcode: &[u8],
    ) -> Result<bool, ExecError> {
        self.check_signature_encoding(sig)?;
        self.check_pubkey_encoding(pk)?;
        let ok = self.check_sig_ecdsa(sig, pk, scriptcode);
        self.last_checks.push(SigCheck { sig: sig.to_vec(), pk: pk.to_vec(), ok });
        Ok(ok)
    }

    fn check_sig_pre_tap(&mut self, sig: &[u8], pk: &[u8]) -> Result<bool, ExecError> {
        let scriptcode = self.script_code_without(&[sig.to_vec()]);
        self.check_sig_with_code(sig, pk, &scriptcode)
    }

    fn check_sig_tap(&mut self, sig: &[u8], pk: &[u8]) -> Result<bool, ExecError> {
        if !sig.is_empty() {
            self.validation_weight -= VALIDATION_WEIGHT_PER_SIGOP_PASSED;
            if self.validation_weight < 0 {
                return Err(ExecError::TapscriptValidationWeight);
            }
        }

        if pk.is_empty() {
            Err(ExecError::PubkeyType)
        } else if pk.len() == 32 {
            if !sig.is_empty() {
                self.check_sig_schnorr(sig, pk)?;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(true)
        }
    }

    fn check_sig(&mut self, sig: &[u8], pk: &[u8]) -> Result<bool, ExecError> {
        match self.ctx {
            ExecCtx::Legacy | ExecCtx::SegwitV0 => self.check_sig_pre_tap(sig, pk),
            ExecCtx::Tapscript => self.check_sig_tap(sig, pk),
        }
    }

    ///////////////
    // EXECUTION //
    ///////////////

    /// Returns true when execution is done.
    pub fn exec_next(&mut self) -> Result<(), &ExecutionResult> {
        if let Some(ref res) = self.result {
            return Err(res);
        }

        self.last_checks.clear();
        self.current_position = self.script.len() - self.instructions.as_script().len();
        let instruction = match self.instructions.next() {
            Some(Ok(i)) => i,
            None => {
                if !self.cond_stack.is_empty() {
                    return self.fail(ExecError::UnbalancedConditional);
                }
                let res = ExecutionResult::from_final_stack(self.ctx, self.stack.clone());
                self.result = Some(res);
                return Err(self.result.as_ref().unwrap());
            }
            Some(Err(_)) => unreachable!("we checked the script beforehand"),
        };

        let exec = self.cond_stack.all_true();
        match instruction {
            Instruction::PushBytes(p) => {
                if p.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return self.fail(ExecError::PushSize);
                }
                if exec {
                    if self.opt.require_minimal && !minimal_push(self.script.as_bytes()[self.current_position], p.as_bytes()) {
                        return self.fail(ExecError::MinimalData);
                    }
                    self.stack.pushstr(p.as_bytes());
                }
            }
            Instruction::Op(op) => {
                // Some things we do even when we're not executing.

                // Note how OP_RESERVED does not count towards the opcode limit.
                if (self.ctx == ExecCtx::Legacy || self.ctx == ExecCtx::SegwitV0)
                    && op.to_u8() > OP_PUSHNUM_16.to_u8()
                {
                    self.opcode_count += 1;
                    if self.opcode_count > MAX_OPS_PER_SCRIPT {
                        return self.fail(ExecError::OpCount);
                    }
                }

                match op {
                    OP_CAT | OP_SUBSTR | OP_LEFT | OP_RIGHT | OP_INVERT | OP_AND | OP_OR | OP_XOR
                    | OP_2MUL | OP_2DIV | OP_MUL | OP_DIV | OP_MOD | OP_LSHIFT | OP_RSHIFT => {
                        return self.failop(ExecError::DisabledOpcode, op);
                    }
                    _ => {}
                }

                if (exec || (op.to_u8() >= OP_IF.to_u8() && op.to_u8() <= OP_ENDIF.to_u8()))
                    && let Err(err) = self.exec_opcode(op)
                {
                    return self.failop(err, op);
                }
            }
        }

        Ok(())
    }
}

/// Decodes an interger in script format with flexible size limit.
///
/// Note that in the majority of cases, you will want to use [`read_scriptint`] instead.
///
/// Panics if max_size exceeds 8.
pub fn read_scriptint_size(v: &[u8], max_size: usize, minimal: bool) -> Result<i64, script::Error> {
    assert!(max_size <= 8);

    if v.len() > max_size {
        return Err(script::Error::NumericOverflow);
    }

    if v.is_empty() {
        return Ok(0);
    }

    if minimal {
        let last = match v.last() {
            Some(last) => last,
            None => return Ok(0),
        };
        // Comment and code copied from Bitcoin Core:
        // https://github.com/bitcoin/bitcoin/blob/447f50e4aed9a8b1d80e1891cda85801aeb80b4e/src/script/script.h#L247-L262
        // If the most-significant-byte - excluding the sign bit - is zero
        // then we're not minimal. Note how this test also rejects the
        // negative-zero encoding, 0x80.
        if (*last & 0x7f) == 0 {
            // One exception: if there's more than one byte and the most
            // significant bit of the second-most-significant-byte is set
            // it would conflict with the sign bit. An example of this case
            // is +-255, which encode to 0xff00 and 0xff80 respectively.
            // (big-endian).
            if v.len() <= 1 || (v[v.len() - 2] & 0x80) == 0 {
                return Err(script::Error::NonMinimalPush);
            }
        }
    }

    Ok(scriptint_parse(v))
}

/// Core's CheckMinimalPush: `data` pushed by the opcode byte `op` the shortest way.
fn minimal_push(op: u8, data: &[u8]) -> bool {
    use bitcoin::opcodes::all::{OP_PUSHDATA1, OP_PUSHDATA2};
    match data {
        [] => op == 0x00,                       // OP_0
        [1..=16] | [0x81] => false,             // OP_1..OP_16, OP_1NEGATE (not pushes here)
        d if d.len() <= 75 => usize::from(op) == d.len(),
        d if d.len() <= 255 => op == OP_PUSHDATA1.to_u8(),
        d if d.len() <= 65535 => op == OP_PUSHDATA2.to_u8(),
        _ => true,
    }
}

/// Caller to guarantee that `v` is not empty.
fn scriptint_parse(v: &[u8]) -> i64 {
    let (mut ret, sh) = v
        .iter()
        .fold((0, 0), |(acc, sh), n| (acc + ((*n as i64) << sh), sh + 8));
    if v[v.len() - 1] & 0x80 != 0 {
        ret &= (1 << (sh - 1)) - 1;
        ret = -ret;
    }
    ret
}

pub(crate) fn read_scriptint(item: &[u8], size: usize, minimal: bool) -> Result<i64, ExecError> {
    read_scriptint_size(item, size, minimal).map_err(|e| match e {
        script::Error::NonMinimalPush => ExecError::MinimalData,
        // only possible if size is 4 or lower
        script::Error::NumericOverflow => ExecError::ScriptIntNumericOverflow,
        // should never happen
        _ => unreachable!(),
    })
}
