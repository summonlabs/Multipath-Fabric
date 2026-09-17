# Multipath Fabric

**Multipath Fabric 1.0.0** is the simultaneous-path-set governance runtime of the
Distributed Fabric Infrastructure / Fabric OS stack, published by
Summon Software Labs as a vendor-neutral C++20 library.

Its single question is:

> Which exact paths belong to this governed multipath set right now, which members are
> currently usable together, under which Path Authority generations and control-plane
> authority, what minimum usable membership is required, and when must a set or member
> be rejected, degraded, fenced, withdrawn, superseded, or revalidated?

Multipath Fabric answers that question with immutable snapshots, deterministic
digests, deterministic diffs, structured outcomes and structured explanations. It
owns no other question.

---

## Table of contents

1. [What Multipath Fabric is](#what-multipath-fabric-is)
2. [The exact boundary](#the-exact-boundary)
3. [Relationships to neighbouring runtimes](#relationships-to-neighbouring-runtimes)
4. [Set identity](#set-identity)
5. [Member identity](#member-identity)
6. [Lifecycle model](#lifecycle-model)
7. [Threshold semantics](#threshold-semantics)
8. [Path Authority binding](#path-authority-binding)
9. [Member currentness](#member-currentness)
10. [Set currentness](#set-currentness)
11. [Generation model](#generation-model)
12. [Authority, epochs and fencing](#authority-epochs-and-fencing)
13. [Revalidation](#revalidation)
14. [Invalidation and watermarks](#invalidation-and-watermarks)
15. [Supersession, revocation and retirement](#supersession-revocation-and-retirement)
16. [Snapshots, diffs and explanations](#snapshots-diffs-and-explanations)
17. [Persistence and recovery](#persistence-and-recovery)
18. [Distributed process model](#distributed-process-model)
19. [Deterministic digest](#deterministic-digest)
20. [Resource limits](#resource-limits)
21. [Deterministic rejection precedence](#deterministic-rejection-precedence)
22. [REAL, SYNTHETIC and UNSUPPORTED validation](#real-synthetic-and-unsupported-validation)
23. [Build](#build)
24. [Test](#test)
25. [Install and find_package](#install-and-find_package)
26. [Command line tools](#command-line-tools)
27. [Examples](#examples)
28. [Benchmarks](#benchmarks)
29. [Genuine limitations](#genuine-limitations)

---

## What Multipath Fabric is

A multipath set is a first-class governed object. It has a stable identity, a
generation, a lifecycle, a scope, a canonical member collection, a minimum
usable-member requirement, provenance, authority and a semantic digest.

Multipath Fabric owns:

* multipath-set identity and lifecycle;
* member identity and exact path membership;
* member, set, membership, authority and Path Authority generation bindings;
* membership publication, replacement and withdrawal;
* set supersession, revocation and retirement;
* simultaneous-use eligibility and member currentness;
* minimum active-member requirements and degraded-set semantics;
* administrative enablement at set and member level;
* canonical membership ordering, provenance and stale rejection;
* invalidation, revalidation, fencing, snapshots, diffs, digests and explanations;
* versioned persistence and conservative recovery;
* real worker-death and coordinator-restart proof;
* single-coordinator distributed mutation authority with mandatory stale-epoch and
  stale-worker rejection.

**A set containing multiple paths is not the same as the paths being legal, the
paths being diverse, the paths being equal-cost, traffic being balanced across
them, the paths carrying equal traffic, the paths being congestion-safe, the paths
having bandwidth reservations, or flows actually using every member.** Multipath
Fabric governs only the middle layer.

## The exact boundary

Multipath Fabric **does not** own, compute or infer:

| Concern | Owner |
| --- | --- |
| canonical entity identity | Fabric Registry |
| structural connectivity and topology | Fabric Topology |
| operational link state | Link State Fabric |
| port configuration | Port Fabric |
| capability truth | Fabric Capability Registry |
| failure-domain truth | Failure Domain Registry |
| epoch authority | Fabric Epoch |
| candidate path computation | Path Planner |
| exact path legality | Path Authority |
| authoritative routes and route lifecycle | Route Fabric |
| equal-cost group semantics, hash domains, buckets | ECMP Governor |
| traffic weighting | Weighted Path Fabric |
| reaction to congestion, latency, telemetry | Adaptive Routing Fabric |
| node/link/SRLG/rack/power diversity analysis | Path Diversity Fabric |

In particular Multipath Fabric never runs Dijkstra or Yen, never searches for
replacement paths, never ranks candidate paths, never installs or withdraws a
route, never decides that members belong together because their costs are equal,
never assigns a traffic weight and never reacts to telemetry.

### Path exists, path is legally usable, path is a member

These are three separate facts owned by three separate runtimes:

~~~/text
PATH EXISTS                    Fabric Topology / Path Planner
PATH IS LEGALLY USABLE         Path Authority
PATH IS A MEMBER               Multipath Fabric   <-- this runtime
MULTIPATH SET IS CURRENT       Multipath Fabric
SET IS SUFFICIENTLY POPULATED  Multipath Fabric
TRAFFIC DISTRIBUTION POLICY    Weighted Path Fabric / ECMP Governor
~~~

## Relationships to neighbouring runtimes

* **Path Planner** computes candidates. Multipath Fabric consumes exact PathId
  values. When a member becomes unusable Multipath Fabric reports the set state
  precisely; asking Path Planner for new candidates is another runtime decision and
  Multipath Fabric never does it on its own.
* **Path Authority** owns exact path legality. Multipath Fabric binds the exact
  PathAuthorityGeneration and the exact reported state into every member. A
  generation mismatch is stale regardless of the reported state, so a historical
  AUTHORIZED result never counts after its generation changed.
* **Route Fabric** owns routes. Multipath Fabric publishes RouteReadiness so Route
  Fabric never has to infer readiness from low-level fields. A ready set means only
  that these exact paths are currently governed members eligible for simultaneous
  use.
* **ECMP Governor** owns equal-cost semantics. Multipath Fabric never decides that
  paths belong together because they are equal cost.
* **Weighted Path Fabric** owns weighting. Multipath Fabric 1.0.0 carries no weight
  metadata at all.
* **Adaptive Routing Fabric** owns reaction policy. Multipath Fabric transitions
  member currentness only when a dependency changes, never in response to
  congestion, latency, queue depth or utilisation.
* **Path Diversity Fabric** owns diversity analysis. Multipath Fabric enforces only
  an explicitly supplied requirement such as "this set requires at least two
  currently usable members"; it never determines whether two paths are disjoint.

## Set identity

~~~cpp
struct SetKey {
  FabricId fabric;
  MultipathNamespace name_space;
  MultipathSetName name;
};
~~~

The semantic key is (fabric, multipath namespace, set name). Generation is **not**
part of identity, and neither is any publisher process incarnation. A set keeps its
identity across ordinary membership mutation; mutation advances generations.
Creating a second set with the same key is rejected with SET_KEY_CONFLICT.

## Member identity

Each membership relation is explicitly identified:

~~~cpp
struct MemberRecord {
  MultipathMemberId id;
  PathId path_id;
  PathAuthorityGeneration bound_authority_generation;
  MultipathMemberGeneration generation;
  MemberLifecycle lifecycle;
  MemberCurrentness currentness;
  bool admin_enabled;
  Watermark invalidation_watermark;
  std::uint32_t pending_revalidations;
  MembershipProvenance provenance;
  std::optional<MultipathMemberId> predecessor;
  std::optional<MultipathMemberId> successor;
  std::optional<PathAuthorityGeneration> observed_authority_generation;
  std::optional<PathAuthorityState> observed_authority_state;
};
~~~

Membership is never identified by vector index. Membership is keyed by the exact
PathId, so **the same exact path may appear at most once in a set**; a duplicate is
rejected with DUPLICATE_MEMBER and never silently counts twice toward a threshold.
Re-admitting a path whose relation was withdrawn replaces the record in place and
records the lineage (predecessor); a withdrawn or superseded relation that is still
retained keeps its own identity.

### Canonical membership order

Members are ordered by PathId (then by member identity if a total order is ever
needed among historical relations). The order does not depend on insertion order,
arrival order or unordered-container iteration, so the same semantic set reached
through different publication orders has the same snapshot representation, diff
ordering and deterministic explanation ordering.

## Lifecycle model

### Set lifecycle

| State | Meaning |
| --- | --- |
| DECLARED | created and durable; membership may be assembled; not offered for use |
| ACTIVE | published and usable members >= minimum requirement |
| DEGRADED | published, at least one usable member, below the minimum |
| EXHAUSTED | published and has zero usable members |
| ADMIN_DISABLED | administrative intent forbids use even though members may be individually authorized |
| WITHDRAWING | withdrawal accepted, not yet complete |
| WITHDRAWN | withdrawal complete; never authoritative again |
| SUPERSEDED | replaced by a successor set; lineage preserved |
| REVOKED | durably, generation-bound revoked with a reason code |
| RETIRED | terminal; never reactivated by any late completion |

The candidate name REVALIDATION_REQUIRED is deliberately **not** a lifecycle state
here: it is a currentness value, because the two facts are independent (see
[Set currentness](#set-currentness)). EXHAUSTED replaces it in the lifecycle because
"published with zero usable members" is a real, distinct shape.

### Member lifecycle

PENDING, CURRENT, REVALIDATION_REQUIRED, UNUSABLE, WITHDRAWN, SUPERSEDED, RETIRED.

### Transition tables

Both lifecycles are driven by an explicit table. There is no path in the engine that
changes a lifecycle outside those tables, and the test suite asserts **every
state/event pair exhaustively** (10 x 18 for sets, 7 x 9 for members) against a
second, independently written table:

~~~text
events        1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 16 17 18
DECLARED      R  P  S  S  S  S  S  S  S  S  S  S  C  R  U  V  T  S
ACTIVE        R  R  C  C  C  C  C  C  X  C  C  S  W  R  U  V  T  C
DEGRADED      R  R  C  C  C  C  C  C  X  C  C  S  W  R  U  V  T  C
EXHAUSTED     R  R  C  C  C  C  C  C  X  C  C  S  W  R  U  V  T  C
ADMIN_DISABLED R R  S  S  S  S  S  S  R  C  S  S  W  R  U  V  T  S
WITHDRAWING   R  R  R  S  R  S  R  R  R  R  R  S  R  D  U  V  T  S
WITHDRAWN     R  R  R  R  R  R  R  R  R  R  R  S  R  R  R  V  T  R
SUPERSEDED    R  R  R  R  R  R  R  R  R  R  R  S  R  R  R  R  T  R
REVOKED       R  R  R  R  R  R  R  R  R  R  R  S  R  R  R  R  T  R
RETIRED       R  R  R  R  R  R  R  R  R  R  R  S  R  R  R  R  R  R

events  1 DECLARE  2 PUBLISH  3 MEMBER_ADDED  4 MEMBER_REMOVED  5 MEMBER_REPLACED
        6 MEMBERSHIP_RECHECK  7 MINIMUM_CHANGED  8 POLICY_CHANGED  9 ADMIN_DISABLED
       10 ADMIN_ENABLED  11 REVALIDATE_SET  12 EPOCH_ADVANCE  13 BEGIN_WITHDRAW
       14 COMPLETE_WITHDRAW  15 SUPERSEDE  16 REVOKE  17 RETIRE  18 DEPENDENCY_INVALIDATED

R REJECT   S STAY   C RECOMPUTE   P BECOME_PUBLISHED   X BECOME_ADMIN_DISABLED
W BECOME_WITHDRAWING   D BECOME_WITHDRAWN   U BECOME_SUPERSEDED
V BECOME_REVOKED   T BECOME_RETIRED
~~~

Terminal set states are fully frozen: a late dependency observation cannot alter a
terminal set recorded state at all, including a member recorded currentness.

## Threshold semantics

minimum_usable_members is an explicit requirement. A published set derives its
lifecycle as:

~~~text
administratively disabled        -> ADMIN_DISABLED
usable >= minimum                -> ACTIVE
usable >= 1 and usable < minimum -> DEGRADED
usable == 0 and minimum >= 1     -> EXHAUSTED
~~~

A minimum of zero means "no minimum requirement", so such a set is ACTIVE as soon as
it is published even with zero usable members.

The test suite walks the complete (members, minimum, unusable) matrix for 0..4
members and 0..4 minimum, including 0/0, 0/1, 1/1, 1/2, 2/2, 2/3, N/N and N-1/N, and
asserts the exact resulting lifecycle, the exact usable count and the
ACTIVE-implies-minimum invariant.

## Path Authority binding

Path Authority integration is a narrow interface:

~~~cpp
struct PathAuthorityView {
  PathId path;
  PathAuthorityGeneration generation;
  PathAuthorityState state;
};

class PathAuthoritySource {
 public:
  virtual std::optional<PathAuthorityView> lookup(const PathId& path) const = 0;
};
~~~

Multipath Fabric calls the source **outside its own lock** and never mutates it. A
deployment installs the real Path Authority client with
FabricEngine::bind_path_authority. By default the engine consumes a
coordinator-owned reference directory (a cache of the exact views the coordinator has
consumed), fed through declare_path_authority and by the DECLARE_PATH_AUTHORITY wire
message. The reference directory is a consumption adapter, not the Path Authority
runtime.

Classification order is exact:

| Observation | Result |
| --- | --- |
| no record for the exact path | PATH_AUTHORITY_UNKNOWN |
| reported generation != bound generation | STALE_PATH_AUTHORITY (generation wins) |
| AUTHORIZED | CURRENT |
| CONDITIONALLY_AUTHORIZED and policy permits | CURRENT |
| CONDITIONALLY_AUTHORIZED and policy does not permit | PATH_CONDITIONALLY_NOT_PERMITTED |
| REVALIDATION_REQUIRED | PATH_REVALIDATION_REQUIRED |
| REJECTED | PATH_REJECTED |
| REVOKED | PATH_REVOKED |
| STALE | PATH_STALE |
| RETIRED | PATH_RETIRED |

The conditional-authority policy is a declared set property; changing it immediately
re-derives every member against its own last observation, so withdrawing permission
stops members counting at once instead of at the next revalidation.

## Member currentness

A member counts toward a threshold only when **both** its lifecycle is CURRENT and
its currentness is CURRENT. Every cause is preserved exactly rather than collapsed
into one "not usable" flag: STALE_PATH_AUTHORITY, PATH_CONDITIONALLY_NOT_PERMITTED,
PATH_REVALIDATION_REQUIRED, PATH_REJECTED, PATH_REVOKED, PATH_STALE, PATH_RETIRED,
PATH_AUTHORITY_UNKNOWN, ADMIN_DISABLED, SET_NOT_USABLE, EPOCH_STALE,
AUTHORITY_FENCED, PENDING_EVALUATION.

Failures that an explicit revalidation can clear (stale generation, path
revalidation required, path stale, unknown path, stale epoch, pending evaluation)
leave the member in REVALIDATION_REQUIRED. Definitive negatives (rejected, revoked,
retired, conditionally not permitted, administratively disabled) leave it UNUSABLE,
and clearing those requires an explicit revalidation.

## Set currentness

SetCurrentness is a second axis, independent of the lifecycle:

* CURRENT -- live currentness is established for the governing epoch and authority.
* REVALIDATION_REQUIRED -- live currentness was lost (coordinator restart, epoch
  advance, fencing of the publisher that last mutated the set) and must be
  re-established by an explicit revalidation.

A set can therefore be ACTIVE with currentness REVALIDATION_REQUIRED immediately
after recovery, and EXHAUSTED with currentness CURRENT. Collapsing the axes would
destroy a distinction that operators depend on.

## Generation model

| Counter | Advances on | Does not advance on |
| --- | --- | --- |
| MultipathSetGeneration | membership add/remove/replace, minimum change, policy change, administrative set change, publication, a published-lifecycle transition caused by a dependency change, revoke/retire/withdraw/supersede | reads, exact replay, unchanged revalidation, epoch advance |
| MembershipGeneration | the exact canonical membership changing (add, remove, replace, withdraw of a live relation) | everything else |
| MultipathMemberGeneration | semantic member mutation (rebind, lifecycle or currentness change, administrative toggle) | unrelated mutation |
| MultipathAuthorityGeneration | publisher registration, unregistration, fencing, epoch advance, store load | membership mutation |
| CoordinatorEpoch | explicit epoch advance and every restart | anything else |

All counters use checked arithmetic and never wrap: an exhausted counter produces a
structured GENERATION_OVERFLOW rejection instead of silent wraparound.

## Authority, epochs and fencing

One coordinator owns mutation authority for a deployment. Multipath Fabric does not
implement consensus and does not claim split-brain prevention between isolated
coordinators. What it does implement is mandatory stale-epoch and stale-worker
rejection.

Every mutation binds a MutationContext:

~~~cpp
struct MutationContext {
  CoordinatorEpoch epoch;
  PublisherId publisher;
  WorkerBootId worker_boot;
  SessionId session;
  MutationAttemptId attempt;
  std::optional<MultipathSetGeneration> expected_set_generation;
  std::optional<MultipathMemberGeneration> expected_member_generation;
};
~~~

* **Being connected is not authority.** A registration binds a publisher and a
  worker boot to the coordinator own session identity; the server rejects any
  request whose session identity is not the connection session.
* **Being known is not authority.** An unregistered or fenced publisher/boot pair is
  rejected at the worker-authority stage.
* **Scope is default-deny.** A registration names a fabric and a multipath
  namespace, optionally restricted to explicit set ids. A set-restricted scope can
  never create a new set, because it cannot identify one.
* **A restarted worker is a new worker.** A fresh WorkerBootId must register again. A
  fenced boot is rejected permanently, for the life of the store.
* **An epoch advance fences everything.** Every registration is dropped and
  permanently fenced, every set records the new epoch and loses live currentness, and
  durable membership description survives untouched.
* **Attempt identity gives exactly-once semantics.** Replaying the same semantic
  request under the same MutationAttemptId returns IDEMPOTENT and advances nothing;
  reusing an attempt id for a different semantic request is rejected with
  ATTEMPT_CONFLICT. The attempt table is bounded by max_attempts; a replay older than
  the retained window is not recognised and is subject to full validation instead.

## Revalidation

* revalidate_set re-evaluates every live member against the current Path Authority
  views, recomputes the lifecycle, enforces the minimum requirement and produces a
  deterministic explanation. It never adds a replacement path.
* revalidate_member rebinds one member to the generation Path Authority reports right
  now and re-derives its currentness.
* A completed evaluation reports MEMBER_REVALIDATED or SET_REVALIDATED (or
  SET_REVALIDATION_INCOMPLETE when a member path had no record), or the negative
  evaluation codes MEMBER_REVALIDATION_NEGATIVE. These are success codes: the
  evaluation completed and the outcome fields plus the explanation carry the verdict.
  A *rejection* is reserved for a request that was refused.

### Two-phase revalidation

~~~cpp
RevalidationBegin begin_member_revalidation(context, set_id, member_id, attempt);
FabricOutcome complete_member_revalidation(context, ticket, current_view);
FabricOutcome abandon_member_revalidation(ticket);
~~~

begin captures the set and member invalidation watermarks plus the epoch; complete
refuses to commit when any of them moved. This is the mechanism that stops a stale
asynchronous completion from resurrecting a member whose Path Authority generation
was superseded while the revalidation was in flight.

## Invalidation and watermarks

Every member carries a monotonic InvalidationWatermark over every input that can make
it usable or unusable; every set carries one too. They are bumped whenever a member
inputs change, when a set-wide event (epoch advance, recovery, withdrawal,
retirement) invalidates in-flight work, and when an observation changes.

When Path Authority reports a new view for an exact path, Multipath Fabric uses the
PathId to set reverse index to touch **only the dependent sets**. An unrelated path
invalidation leaves every other set byte-for-byte unchanged, generation included.

## Supersession, revocation and retirement

* **Supersession** records lineage on both sides and never leaves two simultaneous
  authorities: the predecessor leaves authoritative use in the same commit that
  records the successor. Multipath Fabric 1.0.0 models no overlap transition.
* **Revocation** is durable, idempotent for the same reason code, generation-bound
  and reason-coded (ADMINISTRATIVE, SECURITY, POLICY_VIOLATION, AUTHORITY_REVOKED,
  OPERATOR_REQUEST). It is distinct from member failure, set degradation, path
  invalidation, publisher fencing and retirement: it is a set-level authority act,
  and member records keep their own lifecycle while recording SET_NOT_USABLE.
* **Withdrawal** is two-phase (WITHDRAWING then WITHDRAWN) and marks each member
  WITHDRAWN.
* **Retirement** is terminal and marks each member RETIRED. Late member adds,
  revalidations, publisher retries, administrative toggles and dependency
  invalidations are all refused and change nothing.

## Snapshots, diffs and explanations

* SetSnapshot is an immutable value produced under the engine shared lock. It can
  never expose mutable engine internals and carries no mutation authority.
* The snapshot identity is **content addressed**: "snap-" followed by the 32 hex
  characters of the semantic digest. Identical state always yields the identical
  snapshot identity.
* diff_snapshots produces a deterministic diff with a stable
  (kind, subject, before, after) ordering covering generations, lifecycle,
  currentness, readiness, administrative state, thresholds, policy, epoch,
  supersession, revocation, withdrawal and every per-member field.
* explain_set answers why a set is in its state, which members do not count and
  exactly why, which Path Authority generation is stale, which epoch governs the set
  and which publisher last mutated it. explain_rejection answers why a mutation was
  refused, with the fixed precedence position of the failing stage.

## Persistence and recovery

Format (little-endian, deterministic, version 1):

~~~text
magic         8 bytes  "MPFSTOR" followed by a NUL byte
format        u32
reserved      u32      must be zero
payload_len   u64      bounded
payload       payload_len bytes
checksum      u64      FNV-1a-64 over the 24 header bytes followed by the payload
~~~

Writes are atomic: the new store is written to a temporary file and renamed over the
target, and the previous store is rotated to <path>.bak. When the primary store is
unusable at load time the previous-generation backup is loaded instead and the
recovery reports it. The checksum is a structural integrity check that detects
accidental corruption and truncation; it is **not** cryptographic and Multipath
Fabric makes no authenticity claim based on it.

Decoding rejects, with a structured outcome: empty files, bad magic, unsupported
versions, a non-zero reserved field, truncated headers, truncated payloads, checksum
mismatches, trailing bytes, duplicate set identities, duplicate semantic keys,
duplicate members, dangling members, impossible (zero) generations, malformed
enumerators, invalid thresholds, absurd counts and records above the configured
bounds. Every truncation length of a valid store is exercised by the test suite.

### Conservative recovery

Loading a store restores durable membership **description** only:

* the epoch advances and the authority generation advances;
* every set reports currentness REVALIDATION_REQUIRED and readiness
  REVALIDATION_REQUIRED;
* no publisher registration, session or live authority is restored from disk -- an
  old epoch or old worker boot cannot mutate the recovered state;
* Path Authority views are consumed rather than owned, so the Path Authority bridge
  re-declares the current views before revalidation can restore usability;
* a fenced worker boot stays fenced.

## Distributed process model

~~~text
mpf_coordinator   owns mutation authority, the store and the framed TCP listener
mpf_publisher     a real worker process: registers, mutates, is killed and fenced
mpf               the operator CLI
~~~

Frame layout (little-endian, fixed 24-byte header, wire version 1):

~~~text
[0..4)   magic u32 = 0x5746504D, whose little-endian byte sequence is "MPFW"
[4..6)   wire_version u16
[6..8)   message_id u16   -- explicit stable numeric id, never an enum ordinal
[8..12)  payload_len u32  -- bounded by Limits::max_frame_bytes
[12..16) flags u32        -- must be zero
[16..24) integrity u64    -- FNV-1a-64 over bytes [0..16) followed by the payload
[24..)   payload
~~~

The integrity value covers the semantic header and the payload, so a corrupted length
cannot be used to re-frame a stream. Raw C++ object layouts are never serialized.
Every decoder enforces strict trailing-byte rejection and rejects malformed
enumerators and impossible generations. Message ids are frozen and asserted literally
by the test suite.

### Session lifecycle

The coordinator announces a session identity and the governing epoch in HELLO_ACK
before the client sends anything. Every mutation is bound to the connection that
issued it. When a session ends for any reason -- clean disconnect, peer kill,
protocol failure -- the coordinator fences every worker boot that registered on it,
which is how real worker death becomes a permanent fence.

**Idle sessions stay open.** poll_interval_ms is only a wake-up granularity for
observing shutdown. Once the first byte of a frame has arrived, that frame must
complete within frame_total_timeout_ms; a peer that sends half a frame and stalls
fails with a structured SESSION_TIMEOUT and its session is closed. Windows does not
guarantee that shutdown() alone cancels a blocked recv(), so no receive path relies
on it.

## Deterministic digest

The semantic digest is a 128-bit structural digest (FNV-1a based, rendered as 32 hex
characters) over a canonical byte stream. It is **not** a cryptographic hash and
Multipath Fabric makes no collision-resistance claim for it.

It covers: set identity and the semantic key; lifecycle; currentness; administrative
state; the minimum usable-member requirement; the conditional-authority policy; the
governing epoch; supersession; revocation; the set generation, membership generation
and authority generation; and, in canonical PathId order, every member identity,
path, bound Path Authority generation, member generation, lifecycle, currentness and
administrative state.

It excludes every non-deterministic input: timestamps, socket handles, thread
identities, arrival order, memory addresses and process-local diagnostic counters.
Because the digest deliberately includes the set identity and key, two different sets
never share a digest; **order independence is asserted for a given set**, and the
canonical representation is asserted to be identical across publication
permutations.

## Resource limits

Every limit below is consulted by the code path named in limits.hpp, driven to its
boundary by the test suite, and rejected with a structured RESOURCE_LIMIT (or
INVALID_THRESHOLD) outcome. No configured limit is dead.

~~~text
max_sets=100000                            max_attempts=8192
max_members_per_set=64                     max_pending_revalidations_per_set=64
max_total_members=1000000                  max_path_dependencies_per_path=4096
max_history_per_set=64                     max_snapshot_history=16
max_archived_members_per_set=64            max_scope_set_ids=256
max_frame_bytes=1048576                    max_explanation_entries=512
max_batch_size=256                         max_persistence_record_bytes=16777216
max_publishers=64                          max_store_bytes=67108864
max_sessions=128
~~~

## Deterministic rejection precedence

Every rejection carries the stage that produced it, so a multi-failure input has a
documented, tested answer:

~~~text
1  DECODE             structural validation of the request
2  CALLER_IDENTITY    caller identity present and well formed
3  EPOCH              governing coordinator epoch currency
4  WORKER_AUTHORITY   publisher/boot registration and fencing
5  SCOPE              authority scope over fabric/namespace/set ids
6  ATTEMPT            attempt-id classification (replay or conflict)
7  SET_STATE          set existence and lifecycle admissibility
8  GENERATION         expected set/member generation match
9  PATH_AUTHORITY     exact path authority binding checks
10 RESOURCE_LIMIT     configured capacity limits
11 SEMANTIC           duplicates, thresholds, sizes
12 COMMIT             durable commit of an accepted mutation
~~~

Two deliberate properties of that order:

* **ATTEMPT is classified before GENERATION.** A replay of an already-committed
  mutation necessarily carries the pre-commit expected generation, so classifying
  attempts after the generation check would make exact replay recognition impossible.
* **Every authority check precedes ATTEMPT.** A stale epoch, a fenced boot or an
  out-of-scope caller is rejected even when the attempt id is already known, so a
  stale replay is never accepted merely because its attempt id is recognised. This is
  a tested property, not an implementation detail.

## REAL, SYNTHETIC and UNSUPPORTED validation

**REAL** (genuine, demonstrated in closure):

* real operating-system processes: a coordinator executable, publisher executables and
  a separate test process;
* actual forced operating-system process termination of a live publisher;
* real loopback TCP transport speaking the framed protocol;
* real versioned persistence written to disk and re-read;
* real coordinator restart from the same durable store, repeated across multiple
  restarts with a monotonically advancing epoch;
* the reference Path Authority consumption adapter, exercised through the same
  interface a deployment implements.

**SYNTHETIC** (constructed, and reported as constructed):

* 100 000-set populations created in memory to exercise indexing and scale;
* fabricated fabric-scale PathId values;
* single-host loopback transport observed from one machine.

**UNSUPPORTED** (not implemented, not claimed, not tested):

* physical multi-path switch programming;
* ECMP hardware programming, hashing or bucket assignment;
* weighted traffic distribution, flow hashing or packet striping;
* multi-host network partition testing;
* vendor SDK integration;
* cryptographic authentication of peers;
* consensus or split-brain prevention across isolated coordinators.

A synthetic multipath set is **not** evidence of physical simultaneous forwarding, and
nothing in this repository presents it as such.

## Build

Requirements: CMake 3.20 or newer and a C++20 compiler. Development and closure
validation use MSVC 19.44 (Visual Studio 2022 Build Tools) with
/W4 /WX /permissive- /utf-8.

~~~text
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build
~~~

Options:

| Option | Default | Effect |
| --- | --- | --- |
| MPF_BUILD_TESTS | ON | build the test executables and register them with CTest |
| MPF_BUILD_TOOLS | ON | build mpf, mpf_coordinator and mpf_publisher |
| MPF_BUILD_EXAMPLES | ON | build the examples |
| MPF_BUILD_BENCHMARKS | ON | build mpf_benchmarks |
| MPF_WARNINGS_AS_ERRORS | ON | /WX on MSVC, -Werror elsewhere |
| MPF_ENABLE_ANALYZE | OFF | enable MSVC /analyze |
| MPF_ENABLE_ASAN | OFF | enable AddressSanitizer and deploy its runtime DLL |

## Test

~~~text
ctest --test-dir build --output-on-failure
~~~

Four suites, 122 test cases and about 14 700 recorded expectation checks:

| Suite | Cases | Checks | Covers |
| --- | --- | --- | --- |
| mpf_tests_core | 44 | 2073 | identities, checked arithmetic, lifecycle tables, threshold matrix, membership, authority and precedence |
| mpf_tests_state | 28 | 10240 | invalidation, revalidation, watermarks, deterministic races, barrier races, seeded property schedules |
| mpf_tests_io | 45 | 2107 | resource limits, persistence and corruption, wire framing and codecs, adversarial inputs |
| mpf_tests_distributed | 5 | 270 | real-process worker death, coordinator restart, path invalidation and thresholds, session hardening, repeated connect/disconnect |

There are **no test timeouts of any kind**. A hanging test is a defect. Internal
asynchronous waits are bounded only where exceeding the bound raises an explicit
failed assertion or a structured runtime failure -- for example, waiting for a
coordinator readiness announcement, or waiting for the coordinator to fence a killed
publisher.

### Properties exercised

No duplicate current path member; usable count equals the actual usable members;
usable count never exceeds member count; ACTIVE with currentness CURRENT implies the
minimum requirement is satisfied; a stale Path Authority generation never counts as
usable; a stale worker cannot mutate; a stale epoch cannot mutate; a retired set never
becomes current; an exact replay advances nothing; a set generation never decreases;
generations never wrap; indexes match records; the digest is deterministic;
persistence round-trips; a restart never restores old live worker authority.

### AddressSanitizer

MSVC /fsanitize=address is supported in this environment and is part of closure
validation. Instrumentation is proven with a deliberate heap-buffer-overflow before
the suite is run. The full applicable suite runs under ASan. The sanitizer found two
real product defects during development (a bounds-unaware frame header decoder and a
receive path that tore down idle sessions) and one test-framework defect; all are
fixed and the suite is green under ASan.

## Install and find_package

~~~text
cmake --install build --prefix /path/to/prefix
~~~

~~~cmake
find_package(MultipathFabric CONFIG REQUIRED)
target_link_libraries(app PRIVATE SummonSoftwareLabs::MultipathFabric)
~~~

The installed package exports exactly the imported target
SummonSoftwareLabs::MultipathFabric; the package configuration fails fast if that
target is absent, and MultipathFabricConfigVersion.cmake reports version 1.0.0 with
SameMajorVersion compatibility. The library version, the package version and the CLI
version all come from a single header (multipath_fabric/version.hpp) and cannot drift
apart. The persistence format version and the wire protocol version are versioned
separately from the library version because they have their own compatibility
contracts.

tests/consumer is an independent downstream project that consumes the installed
artifacts only. It configures, compiles, links, creates a synthetic set, adds two exact
path members, queries the state, invalidates one member, observes the exact resulting
state and runs to completion.

## Command line tools

~~~text
mpf version
mpf limits
mpf store inspect PATH
mpf --port N set create --name NAME [--minimum K] [--admin-disabled] [--conditional]
mpf --port N set show SETID | set list | set publish SETID
mpf --port N set withdraw SETID | set complete-withdrawal SETID | set revalidate SETID
mpf --port N set minimum SETID K | set policy SETID authorized|conditional
mpf --port N set enable SETID | set disable SETID
mpf --port N set revoke SETID REASON [--detail TEXT] | set retire SETID [--reason TEXT]
mpf --port N set supersede PREDECESSOR SUCCESSOR
mpf --port N member add SETID PATH GENERATION | member add-bulk SETID PATH:GEN ...
mpf --port N member remove SETID MEMBERID | member withdraw SETID MEMBERID
mpf --port N member revalidate SETID MEMBERID
mpf --port N member replace SETID MEMBERID PATH GENERATION
mpf --port N member enable SETID MEMBERID | member disable SETID MEMBERID
mpf --port N path declare PATH GENERATION STATE | path refresh PATH
mpf --port N authority | epoch advance | snapshot SETID [SNAPSHOTID] | diff SETID | explain SETID
~~~

Output is deterministic and script-friendly: one record per line, no timestamps and no
terminal control sequences. Exit codes: 0 accepted, 1 rejected by the coordinator,
2 malformed invocation, 3 transport failure.

## Examples

Eight examples under examples/, all built and executed as part of closure validation.
Every example uses the public API only and exits successfully.

| Example | Demonstrates |
| --- | --- |
| example_basic_set | create, publish and inspect a set |
| example_membership | add, withdraw, remove, readmit and replace members with lineage |
| example_threshold_degradation | 4/4 to 3/4 to 2/4 to 1/4 to 0/4 against a minimum of two |
| example_stale_path_authority | a stale Path Authority generation stops counting; revalidation rebinds |
| example_worker_reincarnation | fencing a dead boot, a fresh incarnation, restored currentness |
| example_coordinator_restart | conservative recovery, epoch advance, re-declared Path Authority views |
| example_persistence_recovery | store inspection and rejection of a corrupted store |
| example_route_readiness | the Route Fabric consumption surface end to end |

## Benchmarks

mpf_benchmarks counts completed operations only and reports them as measurements of
one machine and one build. They are not service-level objectives and no physical
fabric claim is derived from them. A representative Release run on the validation
machine (16 logical cores, Windows 11, MSVC 19.44):

~~~text
create_set                                    2000 ops   137214 ops/s     7.3 us/op
add_member                                    1600 ops    89832 ops/s    11.1 us/op
query_set (snapshot)                         20000 ops   298159 ops/s     3.4 us/op
snapshot including semantic digest           20000 ops   308702 ops/s     3.2 us/op
explain_set                                   2000 ops   465462 ops/s     2.1 us/op
revalidate_set                                 200 ops   176506 ops/s     5.7 us/op
diff_last_two                                  200 ops   217249 ops/s     4.6 us/op
path invalidation over a large reverse index    50 ops      272 ops/s  3675.3 us/op
create_set at 100k population               100000 ops    82326 ops/s    12.1 us/op
query_set at 100k population                200000 ops   273353 ops/s     3.7 us/op
save store (5000 sets, 20000 members)            1 op       38.5 ops/s   25.98 ms/op
load store (5000 sets, 20000 members)            1 op        3.6 ops/s  276.07 ms/op
~~~

Index integrity at 100 000 sets reports CONSISTENT. The reverse-dependency
invalidation measurement fans one exact path out to 500 dependent sets and includes
the per-set history append, published-lifecycle recomputation, generation advance and
snapshot capture that the product contract requires.

## Genuine limitations

* Multipath Fabric is **not** a consensus system. One coordinator owns mutation
  authority; there is no quorum, no leader election and no protection against two
  isolated coordinators accepting conflicting mutations. Mandatory stale-epoch and
  stale-worker rejection limits the damage of a superseded coordinator but does not
  eliminate it.
* Transport integrity is a non-cryptographic structural checksum. Peers are not
  authenticated and the protocol is not confidential. Deploy it on a trusted or
  separately protected network.
* Persistence integrity is a structural checksum, not a signature. A store is not
  protected against a determined attacker with write access to the file.
* Recovery re-establishes live currentness only after an explicit revalidation, and
  Path Authority views are re-consumed rather than restored from disk. A coordinator
  restart therefore requires the Path Authority bridge to re-declare current views.
* The attempt-id table is bounded. After max_attempts further commits, a replay of an
  older attempt is no longer recognised as a replay and is subject to full validation
  instead.
* History, snapshots and the terminal membership archive are bounded per set; the
  oldest entries are pruned. Recovery depends only on the resulting durable state,
  never on the pruned history.
* Multipath Fabric 1.0.0 carries no traffic weights, no ECMP state, no diversity
  analysis, no route state and no adaptive policy. Any of those appearing in a
  deployment belongs to another runtime.
* Scale figures come from a single host with synthetic members; they say nothing
  about a physical fabric.
* Multipath Fabric has no telemetry transmission of any kind.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
