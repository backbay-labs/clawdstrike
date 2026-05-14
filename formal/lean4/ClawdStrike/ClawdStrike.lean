-- ClawdStrike Formal Verification -- Root import file

import ClawdStrike.Core.Verdict
import ClawdStrike.Core.Aggregate
import ClawdStrike.Core.Merge
import ClawdStrike.Core.Cycle
import ClawdStrike.Core.Eval
import ClawdStrike.Core.Crypto
import ClawdStrike.Core.Receipt
import ClawdStrike.Spec.Properties

-- Proof modules not imported into root to avoid pulling in sorry.
-- Import individually for proof checking:
--   ClawdStrike.Proofs.DenyMonotonicity
--   ClawdStrike.Proofs.CycleTermination
--   ClawdStrike.Proofs.MergeMonotonicity
--   ClawdStrike.Proofs.SeverityOrder
--   ClawdStrike.Proofs.AggregateProperties
--   ClawdStrike.Proofs.ReceiptSigning
--   ClawdStrike.Spec.MerkleProperties
--   ClawdStrike.Proofs.Impl.DenyMonotonicity_Impl
--   ClawdStrike.Proofs.Impl.SpecImplEquiv
--   ClawdStrike.Proofs.Impl.CycleTermination_Impl
