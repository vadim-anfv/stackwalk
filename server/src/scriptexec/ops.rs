use std::cmp;

use bitcoin::hashes::{Hash, hash160, ripemd160, sha1, sha256, sha256d};

use super::*;

impl Exec {
    pub(super) fn exec_opcode(&mut self, op: Opcode) -> Result<(), ExecError> {
        let exec = self.cond_stack.all_true();

        // Remember to leave stack intact until all errors have occurred.
        match op {
            //
            // Push value
            OP_PUSHNUM_NEG1 | OP_PUSHNUM_1 | OP_PUSHNUM_2 | OP_PUSHNUM_3 | OP_PUSHNUM_4
            | OP_PUSHNUM_5 | OP_PUSHNUM_6 | OP_PUSHNUM_7 | OP_PUSHNUM_8 | OP_PUSHNUM_9
            | OP_PUSHNUM_10 | OP_PUSHNUM_11 | OP_PUSHNUM_12 | OP_PUSHNUM_13 | OP_PUSHNUM_14
            | OP_PUSHNUM_15 | OP_PUSHNUM_16 => {
                let n = op.to_u8() - (OP_PUSHNUM_1.to_u8() - 2);
                self.stack.pushnum((n as i64) - 1);
            }

            //
            // Control
            OP_NOP => {}

            OP_CLTV if self.opt.verify_cltv => {
                let top = self.stack.topstr(-1)?;

                // Note that elsewhere numeric opcodes are limited to
                // operands in the range -2**31+1 to 2**31-1, however it is
                // legal for opcodes to produce results exceeding that
                // range. This limitation is implemented by CScriptNum's
                // default 4-byte limit.
                //
                // If we kept to that limit we'd have a year 2038 problem,
                // even though the nLockTime field in transactions
                // themselves is uint32 which only becomes meaningless
                // after the year 2106.
                //
                // Thus as a special case we tell CScriptNum to accept up
                // to 5-byte bignums, which are good until 2**39-1, well
                // beyond the 2**32-1 limit of the nLockTime field itself.
                let n = read_scriptint(&top, 5, self.opt.require_minimal)?;

                if n < 0 {
                    return Err(ExecError::NegativeLocktime);
                }

                if !self.check_lock_time(n) {
                    return Err(ExecError::UnsatisfiedLocktime);
                }
            }
            OP_CLTV => {} // otherwise nop

            OP_CSV if self.opt.verify_csv => {
                let top = self.stack.topstr(-1)?;

                // nSequence, like nLockTime, is a 32-bit unsigned integer
                // field. See the comment in CHECKLOCKTIMEVERIFY regarding
                // 5-byte numeric operands.
                let n = read_scriptint(&top, 5, self.opt.require_minimal)?;

                if n < 0 {
                    return Err(ExecError::NegativeLocktime);
                }

                // with the disable flag set CSV is a NOP (room for soft forks), as in Core
                if n & i64::from(SEQUENCE_LOCKTIME_DISABLE_FLAG) == 0 && !self.check_sequence(n) {
                    return Err(ExecError::UnsatisfiedLocktime);
                }
            }
            OP_CSV => {} // otherwise nop

            OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9 | OP_NOP10 => {
                // reserved for soft forks: policy refuses them so a fork cannot make a relayed tx invalid
                if self.opt.verify_discourage_upgradable_nops {
                    return Err(ExecError::DiscourageUpgradableNops);
                }
            }

            OP_IF | OP_NOTIF => {
                if exec {
                    let top = self.stack.topstr(-1)?;

                    // Tapscript requires minimal IF/NOTIF inputs as a consensus rule.
                    if self.ctx == ExecCtx::Tapscript {
                        // The input argument to the OP_IF and OP_NOTIF opcodes must be either
                        // exactly 0 (the empty vector) or exactly 1 (the one-byte vector with value 1).
                        if top.len() > 1 || (top.len() == 1 && top[0] != 1) {
                            return Err(ExecError::TapscriptMinimalIf);
                        }
                    }
                    // Under segwit v0 only enabled as policy.
                    if self.opt.verify_minimal_if
                        && self.ctx == ExecCtx::SegwitV0
                        && (top.len() > 1 || (top.len() == 1 && top[0] != 1))
                    {
                        return Err(ExecError::TapscriptMinimalIf);
                    }
                    let b = if op == OP_NOTIF {
                        !script::read_scriptbool(&top)
                    } else {
                        script::read_scriptbool(&top)
                    };
                    self.stack.pop().unwrap();
                    self.cond_stack.push(b);
                } else {
                    self.cond_stack.push(false);
                }
            }

            OP_ELSE => {
                if !self.cond_stack.toggle_top() {
                    return Err(ExecError::UnbalancedConditional);
                }
            }

            OP_ENDIF => {
                if !self.cond_stack.pop() {
                    return Err(ExecError::UnbalancedConditional);
                }
            }

            OP_VERIFY => {
                let top = self.stack.topstr(-1)?;

                if !script::read_scriptbool(&top) {
                    return Err(ExecError::Verify);
                } else {
                    self.stack.pop().unwrap();
                }
            }

            OP_RETURN => return Err(ExecError::OpReturn),

            //
            // Stack operations
            OP_TOALTSTACK => {
                let top = self.stack.pop().ok_or(ExecError::InvalidStackOperation)?;
                self.altstack.push(top);
            }

            OP_FROMALTSTACK => {
                let top = self
                    .altstack
                    .pop()
                    .ok_or(ExecError::InvalidStackOperation)?;
                self.stack.push(top);
            }

            OP_2DROP => {
                // (x1 x2 -- )
                self.stack.needn(2)?;
                self.stack.popn(2).unwrap();
            }

            OP_2DUP => {
                // (x1 x2 -- x1 x2 x1 x2)
                let x1 = self.stack.top(-2)?.clone();
                let x2 = self.stack.top(-1)?.clone();
                self.stack.push_copy(&x1);
                self.stack.push_copy(&x2);
            }

            OP_3DUP => {
                // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                let x1 = self.stack.top(-3)?.clone();
                let x2 = self.stack.top(-2)?.clone();
                let x3 = self.stack.top(-1)?.clone();
                self.stack.push_copy(&x1);
                self.stack.push_copy(&x2);
                self.stack.push_copy(&x3);
            }

            OP_2OVER => {
                // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                self.stack.needn(4)?;
                let x1 = self.stack.top(-4)?.clone();
                let x2 = self.stack.top(-3)?.clone();
                self.stack.push_copy(&x1);
                self.stack.push_copy(&x2);
            }

            OP_2ROT => {
                // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                self.stack.needn(6)?;
                let x6 = self.stack.pop().unwrap();
                let x5 = self.stack.pop().unwrap();
                let x4 = self.stack.pop().unwrap();
                let x3 = self.stack.pop().unwrap();
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x3);
                self.stack.push(x4);
                self.stack.push(x5);
                self.stack.push(x6);
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_2SWAP => {
                // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                self.stack.needn(4)?;
                let x4 = self.stack.pop().unwrap();
                let x3 = self.stack.pop().unwrap();
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x3);
                self.stack.push(x4);
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_IFDUP => {
                // (x - 0 | x x)
                let top = self.stack.topstr(-1)?;
                if script::read_scriptbool(&top) {
                    let top = self.stack.top(-1)?.clone();
                    self.stack.push_copy(&top);
                }
            }

            OP_DEPTH => {
                // -- stacksize
                self.stack.pushnum(self.stack.len() as i64);
            }

            OP_DROP => {
                // (x -- )
                if self.stack.pop().is_none() {
                    return Err(ExecError::InvalidStackOperation);
                }
            }

            OP_DUP => {
                // (x -- x x)
                let top = self.stack.top(-1)?.clone();
                self.stack.push_copy(&top);
            }

            OP_NIP => {
                // (x1 x2 -- x2)
                self.stack.needn(2)?;
                let x2 = self.stack.pop().unwrap();
                self.stack.pop().unwrap();
                self.stack.push(x2);
            }

            OP_OVER => {
                // (x1 x2 -- x1 x2 x1)
                let under_top = self.stack.top(-2)?.clone();
                self.stack.push_copy(&under_top);
            }

            OP_PICK | OP_ROLL => {
                // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                // as Core: two elements first, then n is popped and checked against what is left
                self.stack.needn(2)?;
                let x = self.stack.topnum(-1, self.opt.require_minimal)?;
                self.stack.pop().unwrap();
                if x < 0 || x >= self.stack.len() as i64 {
                    return Err(ExecError::InvalidStackOperation);
                }
                if op == OP_ROLL {
                    let elem = self.stack.remove(self.stack.len() - x as usize - 1);
                    self.stack.push(elem);
                } else {
                    let elem = self.stack.top(-x as isize - 1).unwrap().clone();
                    self.stack.push_copy(&elem);
                }
            }

            OP_ROT => {
                // (x1 x2 x3 -- x2 x3 x1)
                self.stack.needn(3)?;
                let x3 = self.stack.pop().unwrap();
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x2);
                self.stack.push(x3);
                self.stack.push(x1);
            }

            OP_SWAP => {
                // (x1 x2 -- x2 x1)
                self.stack.needn(2)?;
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push(x2);
                self.stack.push(x1);
            }

            OP_TUCK => {
                // (x1 x2 -- x2 x1 x2)
                self.stack.needn(2)?;
                let x2 = self.stack.pop().unwrap();
                let x1 = self.stack.pop().unwrap();
                self.stack.push_copy(&x2);
                self.stack.push(x1);
                self.stack.push(x2);
            }

            OP_SIZE => {
                // (in -- in size)
                let top = self.stack.topstr(-1)?;
                self.stack.pushnum(top.len() as i64);
            }

            //
            // Bitwise logic
            OP_EQUAL | OP_EQUALVERIFY => {
                // (x1 x2 - bool)
                self.stack.needn(2)?;
                let x2 = self.stack.popstr().unwrap();
                let x1 = self.stack.popstr().unwrap();
                let equal = x1 == x2;
                if op == OP_EQUALVERIFY && !equal {
                    return Err(ExecError::EqualVerify);
                }
                if op == OP_EQUAL {
                    let item = if equal { 1 } else { 0 };
                    self.stack.pushnum(item);
                }
            }

            //
            // Numeric
            OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                // (in -- out)
                let x = self.stack.topnum(-1, self.opt.require_minimal)?;
                let res = match op {
                    OP_1ADD => x
                        .checked_add(1)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_1SUB => x
                        .checked_sub(1)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_NEGATE => x.checked_neg().ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_ABS => x.abs(),
                    OP_NOT => (x == 0) as i64,
                    OP_0NOTEQUAL => (x != 0) as i64,
                    _ => unreachable!(),
                };
                self.stack.pop().unwrap();
                self.stack.pushnum(res);
            }

            OP_ADD
            | OP_SUB
            | OP_BOOLAND
            | OP_BOOLOR
            | OP_NUMEQUAL
            | OP_NUMEQUALVERIFY
            | OP_NUMNOTEQUAL
            | OP_LESSTHAN
            | OP_GREATERTHAN
            | OP_LESSTHANOREQUAL
            | OP_GREATERTHANOREQUAL
            | OP_MIN
            | OP_MAX => {
                // (x1 x2 -- out)
                let x1 = self.stack.topnum(-2, self.opt.require_minimal)?;
                let x2 = self.stack.topnum(-1, self.opt.require_minimal)?;
                let res = match op {
                    OP_ADD => x1
                        .checked_add(x2)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_SUB => x1
                        .checked_sub(x2)
                        .ok_or(ExecError::ScriptIntNumericOverflow)?,
                    OP_BOOLAND => (x1 != 0 && x2 != 0) as i64,
                    OP_BOOLOR => (x1 != 0 || x2 != 0) as i64,
                    OP_NUMEQUAL => (x1 == x2) as i64,
                    OP_NUMEQUALVERIFY => (x1 == x2) as i64,
                    OP_NUMNOTEQUAL => (x1 != x2) as i64,
                    OP_LESSTHAN => (x1 < x2) as i64,
                    OP_GREATERTHAN => (x1 > x2) as i64,
                    OP_LESSTHANOREQUAL => (x1 <= x2) as i64,
                    OP_GREATERTHANOREQUAL => (x1 >= x2) as i64,
                    OP_MIN => cmp::min(x1, x2),
                    OP_MAX => cmp::max(x1, x2),
                    _ => unreachable!(),
                };
                if op == OP_NUMEQUALVERIFY && res == 0 {
                    return Err(ExecError::NumEqualVerify);
                }
                self.stack.popn(2).unwrap();
                if op != OP_NUMEQUALVERIFY {
                    self.stack.pushnum(res);
                }
            }

            OP_WITHIN => {
                // (x min max -- out)
                let x1 = self.stack.topnum(-3, self.opt.require_minimal)?;
                let x2 = self.stack.topnum(-2, self.opt.require_minimal)?;
                let x3 = self.stack.topnum(-1, self.opt.require_minimal)?;
                self.stack.popn(3).unwrap();
                let res = x2 <= x1 && x1 < x3;
                let item = if res { 1 } else { 0 };
                self.stack.pushnum(item);
            }

            //
            // Crypto

            // (in -- hash)
            OP_RIPEMD160 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(ripemd160::Hash::hash(&top[..]).to_byte_array().as_ref());
            }
            OP_SHA1 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(sha1::Hash::hash(&top[..]).to_byte_array().as_ref());
            }
            OP_SHA256 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(sha256::Hash::hash(&top[..]).to_byte_array().as_ref());
            }
            OP_HASH160 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(hash160::Hash::hash(&top[..]).to_byte_array().as_ref());
            }
            OP_HASH256 => {
                let top = self.stack.popstr()?;
                self.stack
                    .pushstr(sha256d::Hash::hash(&top[..]).to_byte_array().as_ref());
            }

            OP_CODESEPARATOR => {
                // Store this CODESEPARATOR position and update the scriptcode.
                self.last_codeseparator_pos = Some(self.current_position as u32);
                // as Core: the script code starts after the separator, not at it
                self.script_code = &self.script[self.current_position + 1..];
            }

            OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                let sig = self.stack.topstr(-2)?.clone();
                let pk = self.stack.topstr(-1)?.clone();
                let res = self.check_sig(&sig, &pk)?;
                if !res && self.opt.verify_nullfail && self.ctx != ExecCtx::Tapscript && !sig.is_empty() {
                    return Err(ExecError::NullFail);
                }
                self.stack.popn(2).unwrap();
                if op == OP_CHECKSIGVERIFY && !res {
                    return Err(ExecError::CheckSigVerify);
                }
                if op == OP_CHECKSIG {
                    let ret = if res { 1 } else { 0 };
                    self.stack.pushnum(ret);
                }
            }

            OP_CHECKSIGADD => {
                if self.ctx == ExecCtx::Legacy || self.ctx == ExecCtx::SegwitV0 {
                    return Err(ExecError::BadOpcode);
                }
                let sig = self.stack.topstr(-3)?.clone();
                let mut n = self.stack.topnum(-2, self.opt.require_minimal)?;
                let pk = self.stack.topstr(-1)?.clone();
                let res = self.check_sig(&sig, &pk)?;
                self.stack.popn(3).unwrap();
                if res {
                    n += 1;
                }
                self.stack.pushnum(n);
            }

            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                // Port of Bitcoin Core interpreter.cpp (EvalScript, OP_CHECKMULTISIG).
                if self.ctx == ExecCtx::Tapscript {
                    return Err(ExecError::TapscriptCheckMultiSig);
                }
                let mut i: usize = 1;
                self.stack.needn(i)?;
                let mut n_keys = self.stack.topnum(-(i as isize), self.opt.require_minimal)?;
                if !(0..=MAX_PUBKEYS_PER_MULTISIG).contains(&n_keys) {
                    return Err(ExecError::PubkeyCount);
                }
                self.opcode_count += n_keys as usize;
                if self.opcode_count > MAX_OPS_PER_SCRIPT {
                    return Err(ExecError::OpCount);
                }
                i += 1;
                let mut ikey = i;
                // ikey2 is the position of last non-signature item in the stack. Top stack item = 1.
                // With SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if operation fails.
                let mut ikey2 = n_keys as usize + 2;
                i += n_keys as usize;
                self.stack.needn(i)?;
                let mut n_sigs = self.stack.topnum(-(i as isize), self.opt.require_minimal)?;
                if n_sigs < 0 || n_sigs > n_keys {
                    return Err(ExecError::SigCount);
                }
                i += 1;
                let mut isig = i;
                i += n_sigs as usize;
                self.stack.needn(i)?;

                // Drop the signatures in pre-segwit scripts but not segwit scripts.
                let sigs: Vec<Vec<u8>> =
                    (0..n_sigs as usize).map(|k| self.stack.topstr(-((isig + k) as isize)).unwrap()).collect();
                let scriptcode = self.script_code_without(&sigs);

                let mut success = true;
                while success && n_sigs > 0 {
                    let sig = self.stack.topstr(-(isig as isize))?;
                    let pk = self.stack.topstr(-(ikey as isize))?;
                    // Note how this makes the exact order of pubkey/signature evaluation
                    // distinguishable by CHECKMULTISIG NOT if the STRICTENC flag is set.
                    let ok = self.check_sig_with_code(&sig, &pk, &scriptcode)?;
                    if ok {
                        isig += 1;
                        n_sigs -= 1;
                    }
                    ikey += 1;
                    n_keys -= 1;
                    // If there are more signatures left than keys left, then too many
                    // signatures have failed. Exit early, without checking any further
                    // signatures.
                    if n_sigs > n_keys {
                        success = false;
                    }
                }

                // Clean up stack of actual arguments
                while i > 1 {
                    i -= 1;
                    // If the operation failed, we require that all signatures must be empty vector
                    if !success
                        && self.opt.verify_nullfail
                        && ikey2 == 0
                        && !self.stack.topstr(-1)?.is_empty()
                    {
                        return Err(ExecError::NullFail);
                    }
                    ikey2 = ikey2.saturating_sub(1);
                    self.stack.pop().unwrap();
                }

                // A bug causes CHECKMULTISIG to consume one extra argument
                // whose contents were not checked in any way.
                self.stack.needn(1)?;
                if self.opt.verify_nulldummy && !self.stack.topstr(-1)?.is_empty() {
                    return Err(ExecError::NullDummy);
                }
                self.stack.pop().unwrap();

                if op == OP_CHECKMULTISIGVERIFY {
                    if !success {
                        return Err(ExecError::CheckMultiSigVerify);
                    }
                } else {
                    self.stack.pushnum(if success { 1 } else { 0 });
                }
            }

            // remainder
            _ => return Err(ExecError::BadOpcode),
        }

        if self.opt.enforce_stack_limit && self.stack.len() + self.altstack.len() > MAX_STACK_SIZE {
            return Err(ExecError::StackSize);
        }

        Ok(())
    }
}
