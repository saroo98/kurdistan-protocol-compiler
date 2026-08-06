# Phase 16 Key Ceremonies

> **Realignment notice:** KIP-0093 replaces mandatory centralized roles and
> cloud-HSM ceremonies with a single-owner deployment root, encrypted recovery
> artifact, bounded online issuer, and optional hardware-key adapters. This
> historical procedure is not current deployment authority.

Every root, recovery, issuer, emergency, publication, audit, and destruction
ceremony requires two distinct approvers and a separate executor. Actor aliases
are opaque. Names, email addresses, token claims, private keys, and credentials
must not enter Git, logs, receipts, command lines, or artifacts.

## Receipt contract

Each ceremony receipt binds the exact source tree, infrastructure plan,
operation and approval IDs, HSM key-version resource, public-key digest,
algorithm, protection-level readback, trusted start/end sequence, before/after
state, and independent verifier result. A receipt is invalid if any field is
missing, duplicated, stale, or bound to another environment.

## Lifecycle

`CREATED -> STAGED -> DUAL_APPROVED -> PRIMARY -> RETIRING -> DISABLED -> DESTROY_SCHEDULED -> DESTROYED`

Promotion to `PRIMARY` requires monotonic authority publication plus CLI and
Android verification. Destruction is never automatic. Phase 16 qualifies
scheduling and cancellation with disposable keys; actual production
destruction needs a separate irreversible-action authorization.

## Break glass

Break glass is deny-oriented, time bounded, separately alerted, and cannot
grant root, recovery, or ordinary issuance authority. It expires automatically
and requires retrospective review of the complete anchor chain.
