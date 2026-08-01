# OpsHaven installation state model

OpsHaven evaluates one installation from independently verifiable evidence. No command may infer readiness from a single marker, a successful prior command, or the absence of one receipt.

## Authority rules

1. The installed artifacts and their measured identities are authoritative for what is active.
2. The canonical remote-state record and generation receipt are authoritative only when both exist and match the measured artifacts.
3. The synchronization transaction is authoritative for an interrupted mutation and rollback availability. It is not proof that an otherwise damaged installation is healthy.
4. Local configuration and application registration are desired-state inputs, not proof of remote readiness.
5. Deployment plans are immutable, expiring execution authorizations. They never repair or redefine installation health.
6. Audit records preserve evidence and continuity. They cannot convert invalid runtime or receipt evidence into a healthy state.
7. Unknown, partial, unsafe, or conflicting evidence fails closed.

## State inventory

| State source | Owner and storage | Schema | Writer | Readers | Authority and reconstruction | Migration, failure, and repair |
| --- | --- | --- | --- | --- | --- | --- |
| Local operator marker | Operator, `~/.config/opshaven/state.json` | local state v1 | `opshaven init` | init, doctor, setup path resolution | Cached workflow marker. Reconstructable only from separately validated local files. | Invalid or partial local state blocks guided setup and must be rebuilt without changing remote evidence. |
| Local policy | Operator, `~/.config/opshaven/config.json` | policy v1 plus policy version | init and `app add` | every local operation, doctor, deployment | Authoritative desired local policy. Not evidence of remote installation. | Atomic owner-only replacement; malformed or unsafe files fail closed. |
| Remote deployment policy copy | Operator, sibling `config.json.dispatcher.json` | policy v1 plus policy version | init and `app add` | setup planning, capability generation | Authoritative desired remote policy before signing and synchronization. | Must remain identity-aligned with application registration and declarations. |
| Local setup configuration | Operator, `~/.config/opshaven/setup.json` | setup v1 | init / guided setup completion | setup, repair, doctor, boundary, deploy gating | Authoritative target binding: pinned host, fixed paths, reviewed source identity. | Invalid or outdated configuration requires guided local repair; it never authorizes guessed remote paths. |
| Operator and restricted SSH keys | Operator, `~/.config/opshaven/keys/` | PEM/OpenSSH formats | init | signing, restricted SSH, doctor | Authoritative local key material when regular, non-symlinked, and correctly permissioned. | A partial key pair is invalid and must not be silently regenerated over surviving evidence. |
| Application registrations | Operator, `~/.config/opshaven/deployment/applications/` | application v1 | `opshaven app add` | doctor, deploy plan/apply, setup desired scope | Authoritative local application intent and resource binding. Also bound into protected policy files. | Registration is atomic and local-only. Binding drift invalidates deployment readiness until reviewed synchronization. |
| Stored deployment plans | Operator, `~/.config/opshaven/deployment/plans/` | deployment plan v1 | `opshaven deploy plan` | exact-plan apply | Immutable cached authorization bound to observed state, target revision, operations, policy, application, expiry, and nonce. | Not migratable by inference. Expired, changed, malformed, or mismatched plans are rejected and recreated. |
| Deployment execution records | Operator, `~/.config/opshaven/deployment/executions/` | execution v1 | deploy apply | audit and retry safety | Evidence of start/result, not proof of current remote health. | Preserved on failure. Exact state is re-inspected before any later apply. |
| Runtime manifest | Remote, `/var/lib/opshaven/runtime-manifest.json` | runtime manifest | setup staging/activation | installed-state measurement, generation receipt construction | Measured runtime input. Reconstructable only by hashing the installed reviewed runtime tree. | Missing or unsafe manifest with remaining managed artifacts is damaged state, not an absent installation. |
| Active runtime and dispatcher | Remote, fixed runtime root under `/usr/lib/opshaven` | reviewed build artifacts | transactional setup | dispatcher, doctor, boundary, health evaluator | Authoritative active bytes. Digests must match signed/canonical evidence. | Legacy read-only or split dispatcher shapes require explicit classification; unknown layouts fail closed. |
| Authorization and declaration artifacts | Remote, fixed `/etc/opshaven` paths | signed capability and declaration schemas | transactional setup | dispatcher, doctor, boundary, health evaluator | Authoritative only after signature, binding, scope, and digest verification. | Missing, partial, or mismatched artifacts invalidate deployment readiness and select repair or migration. |
| Canonical remote state | Remote, `/var/lib/opshaven/remote-state.json` | remote state v3 | post-verification setup commit | setup planning, doctor, boundary, deploy gating | Canonical generation metadata only when paired with a valid setup receipt and matching measured artifacts. | Older known schemas require explicit migration. A lone state file is `REMOTE_GENERATION_PARTIAL`. |
| Setup receipt | Remote, configured setup receipt path | setup receipt / rollback evidence | setup and rollback | installed-state inspection, repair, boundary | Canonical certification evidence only when paired with remote state and matching active artifacts. | A lone receipt, missing receipt with managed artifacts, malformed receipt, or invalid rollback chain requires repair. |
| Managed-path footprint | Remote, fixed OpsHaven-owned paths only | footprint v1 | read-only evaluator | global health, repair | Derived cache used to distinguish truly empty, canonical, known legacy, partial, and unsafe installations. | Reconstructed on every health check with `lstat`; symbolic links or unsupported objects become uncertain state. |
| Synchronization transaction | Remote, `/var/lib/opshaven/synchronization-transaction.json` | transaction v1 | transactional setup/rollback | setup, repair, doctor, boundary, deploy gating | Authoritative for phase, host binding, desired/previous generation identities, and rollback snapshot. | Missing marker does not imply health. Invalid/stale markers fail closed; verified interrupted transactions select bounded completion or rollback. |
| Previous-generation snapshot | Remote, `/var/lib/opshaven/transactions/<id>/previous/` | snapshot manifest v1 | transaction `RECORD_PREVIOUS` | rollback and repair | Immutable rollback material when manifest, digests, transaction binding, and receipt chain all verify. | Never guessed. Invalid or unavailable snapshots select evidence-preserving reinstall or manual recovery. |
| Recovery evidence | Remote, `/var/lib/opshaven/recovery-evidence/<id>/` | evidence manifest v1 | reviewed repair | operator audit/review | Preserved copy of managed active state and transaction history before bounded clean reinstall preparation. | Manifest is written and verified before fixed active paths are removed. Evidence is not deleted by repair. |
| Audit chain | Configured owner-only audit JSONL | chained audit events | all security-sensitive commands | doctor, deploy, verification | Tamper-evident history. Required for operation authorization but not a substitute for active-state verification. | Invalid continuity blocks mutation. Repair appends evidence rather than rewriting history. |

## Canonical health evaluation

`src/setup/health.ts` combines three readers on every remote health decision:

- measured installed state;
- synchronization transaction inspection;
- fixed managed-path footprint.

The evaluator returns one ordered set of stable states and one repair classification. Setup, repair, doctor, boundary verification, deployment planning, and deployment apply consume that result.

A serious state is never hidden by a nearer workflow problem. For example, `REMOTE_GENERATION_PARTIAL` remains the primary diagnosis even when no application is registered. Application onboarding is then reported as a separate lower-priority deployment issue.

## Migration policy

Known historical shapes are classified explicitly:

- read-only dispatcher without canonical generation records: legacy migration;
- split dispatcher architecture: legacy migration only when every expected artifact is recognized;
- pre-v3 complete state: explicit schema synchronization;
- receipt bound to obsolete staging paths: repair or evidence-preserving reinstall;
- one of remote state or setup receipt missing: partial generation, never fresh install;
- interrupted transaction with verified previous snapshot: exact previous-generation restoration;
- interrupted transaction without verified rollback: bounded evidence-preserving reinstall;
- unknown paths, symbolic links, unsupported objects, or unrecognized schemas: manual reviewed recovery.

No migration may manufacture missing generation identity, suppress receipt validation, delete audit evidence, or select a rollback generation by recency.

## Readiness invalidators

Deployment and boundary certification are blocked by any of:

- incomplete or invalid synchronization transaction;
- partial generation identity;
- receipt or recorded-identity mismatch;
- unknown or unsafe managed footprint;
- unsupported or unclassified legacy state;
- canonical desired/installed incompatibility;
- invalid audit continuity;
- missing signed authorization or application-scope binding.

A healthy no-change rerun still measures the active installation and verifies canonical evidence. It does not trust the prior command result.

## Remaining trust assumptions

- The pinned SSH host key identifies the intended machine.
- The fixed administrator transport and reviewed privilege boundary execute the supplied bounded Python inspectors without an already-compromised host falsifying all local observations.
- The local operator machine protects owner-only keys and configuration from a hostile local administrator.
- Node.js and Python executables selected through fixed reviewed paths behave according to their platform contracts.
- Filesystem durability follows successful `fsync` and atomic rename semantics on supported Linux filesystems.

## Deployment plan identity and volatile readiness

Exact stale-plan identity binds the registered application and release layout, pinned host identity, current revision, active release and rollback target, service state, runtime readiness, policy and authorization profile, operation definitions, and health-check definition. Dispatcher, capability, declaration, receipt, and application-scope identities are verified by the canonical installation-health preflight before planning or apply.

The plan records observed free disk space for operator review and audit, but exact free-byte counts are volatile and are not part of the observed-state fingerprint. At apply time OpsHaven re-inspects the host and requires `availableDiskBytes >= DEPLOYMENT_MINIMUM_DISK_BYTES` before any deployment mutation. Clock time, latency, temporary load, transient response timing, and temporary paths are likewise not deployment identity.
