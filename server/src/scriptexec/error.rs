use bitcoin::blockdata::script;

/// Error of a script execution.
///
/// Equivalent to Bitcoin Core's `ScriptError_t`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    DisabledOpcode,
    BadOpcode,
    OpCount,
    PushSize,
    MinimalData,
    InvalidStackOperation,
    NegativeLocktime,
    UnsatisfiedLocktime,
    UnbalancedConditional,
    TapscriptMinimalIf,
    Verify,
    OpReturn,
    EqualVerify,
    NumEqualVerify,
    CheckSigVerify,
    TapscriptValidationWeight,
    PubkeyType,
    SchnorrSigSize,
    SchnorrSigHashtype,
    SchnorrSig,
    TapscriptCheckMultiSig,
    PubkeyCount,
    StackSize,
    ScriptSize,
    WitnessPubkeyType,
    SigDer,
    SigHighS,
    SigHashtype,
    DiscourageUpgradableNops,

    SigCount,
    NullFail,
    NullDummy,
    CheckMultiSigVerify,

    // new ones for us
    ScriptIntNumericOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidScript(script::Error),
    Other(&'static str),
}
