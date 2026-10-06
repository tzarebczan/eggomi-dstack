# CAH authority model

This note supersedes two claims in
[docs/eggomi/ARCHITECTURE.md](../eggomi/ARCHITECTURE.md):

- keeper exposing a live secret API such as `get_secret`,
  `mint_session_token`, or `list_connections`
- branching a live keeper by checkpoint and treating that branch as ordinary
  scaling

WS1 forbids both. The host-native Eggomi profile on this branch follows the
rules below. Older sentences in the Eggomi architecture that still name those
APIs are historical sketch text, not the model this stack runs.

## Who chooses authority

`PrepareUse` may repeat origin, resource handle, policy revision, lease,
audience, field, tenant, and recipient. Keeper loads the current
`cah-keeper-policy/v1` revision from its private directory on that call.
Nothing is cached. A mismatch, including an origin the requester invented,
is `denied_payload` and stores no grant. Frame id and navigation generation
are taken from the policy, not from the omi body. Admission does not read
the policy directory. The launcher does not install the profile fixture as
the live authority file. A test double calls `publish_revision` to simulate
the keeper write.

The runtime allow graph stays `service-access/v1`. The mapping to
`eggomi/workload-service-access/v1` is
`test-suites/cah/profiles/eggomi/service-access-map.json`. Three edges are
explicit deviations and are not silent replacements of the WS1 file:

| Runtime edge | WS1 direction this stub does not implement |
| --- | --- |
| `credential-broker` → keeper `ResolveUseGrant` | keeper → broker `AuthorizeUse` |
| browser → keeper `ReportOutcome` | keeper → browser `ExecuteBrowserOperation` |
| browser → keeper `QueryOutcome` | WS1 has no separate outcome query |
| launcher writes and signs the registry in-process (`launcher_sig`) | launcher → identity-service `IssueForVerifiedLaunch` |

The opaque grant stays in keeper. The broker asks keeper to consume it.

## Registry attribution

Every `admission-registry/v1` row carries `launcher_sig`: Ed25519 (RFC 8032,
pure) by the launcher's host key, 128 lowercase hex characters. The signed
bytes are the UTF-8 encoding of `"eggomi/admission-row/v1\n"` followed by
a compact JSON array, in `JSON.stringify` encoding, of `trust_domain` and
`tenant` (from the document), `role`, `instance_id`, `boot_id`,
`boot_generation`, `boot_history`, `channel_public`, `cert_fingerprint`,
`pid` and `starttime`. That is Eggomi's `rowMessage`
(`apps/desktop/src/keeper/cah/registry.ts`), and
`test-suites/cah/vectors/eggomi-interop.json` holds signatures both sides
reproduce. The launcher refuses to sign a row Eggomi's `parseRow` would call
malformed.

The private key is `state/launcher/row-signing.key`, a sibling of
`authority/` and `host-fence/`, hidden from every confined compartment.
keeper-core, the other servers and the clients are configured with the
32-byte public key (`--launcher-public`). The registry never names it. A
lookup only returns rows whose signature verifies, so an unsigned, edited or
foreign-signed row is no identity: the pidfd gate refuses its peer with
`denied_unadmitted`, and resolve does not find it as a recipient. An
instance, channel key or fingerprint that two signed rows claim is no
identity for either. A reader also remembers, per registry file and in
memory, the highest generation and the boot ids each instance left. A
signed row older than one it already read is no identity, so writing an
earlier signed registry back does not revive an old incarnation for a
reader that saw the newer one. A restarted reader starts empty. That is the
same scope as Eggomi's in-memory `Watermarks`.

The launcher only rewrites a file whose every row it signed. A row someone
else put in the registry makes the next launcher write fail
(`RegistryTampered`) instead of being signed with the rest. A channel key
must be canonical (64 lowercase hex, top bit clear, below 2^255 - 19), so
no other spelling of one X25519 key can be bound to a second owner.

The launcher also refuses to sign a row whose channel key or certificate
fingerprint was ever signed for another instance or role. The first owner
wins, permanently, even after its row is gone, so a clone launched with its
parent's key does not speak as the parent. That memory is
`state/launcher/key-owners.jsonl`: append-only, each new owner fsynced
(with its directory entry on create) before the registry that names it is
written, outside `authority/` and outside the registry. Restoring
`authority/`, or rewriting or deleting the registry, does not clear it. An
instance may return to its own earlier key (A → B → A); that still advances
`boot_generation`.

## Recipient binding

A grant is issued only when the recipient already has a channel public key,
a certificate fingerprint, or a pid plus start time. Resolve identifies the
presenter by a possession proof over the guard's lease key, then checks the
registry row for that key. Body fields named `observed_*` are refused.
A null fingerprint does not skip the check.

A second admitted `browser-guard` that presents a copied `grant_ref` is
`denied_recipient` at resolve. The grant stays issued for the bound
recipient. An `omi-runner` call to the broker is a different check: the
access graph returns `denied_role` before the grant is examined.

Rebinding a pid, a start time, or a certificate fingerprint advances
`boot_generation` and revokes that instance's issued grants. A fingerprint
change is a rebind whether or not the row already has a pid. Any change to a
stored identity field advances the generation, including the first bind that
records a pid, a fingerprint or a channel key on a row that has none (the
launcher reports it as `bound`, not `rebound`). That is Eggomi's rule: its
keeper refuses an incarnation change at the same generation
(`rebind_without_generation`). Repeating the stored values does not
advance. `set_boot` accepts only a boot id that is not already in
`boot_history`. Repeating an older id raises `BootRollback`. A generation
mismatch on resolve is terminal `denied_boot`. Returning to an earlier
fingerprint does not revive a grant that the rebind revoked. `denied_boot`
is the only wire code for that outcome.

`CompleteFill` carries a proof and the live frame. Keeper compares frame and
navigation to `destination_binding`. A mismatch is `denied_payload` and does
not consume the grant. On success the answer is one sealed credential. The
broker forwards it and does not hold the plaintext. The guard rebuilds the
associated data from its lease, its registry row, and the operation it is
running. The lease carries the profile-lease fence, the lease epoch, and the
keeper boot epoch it was granted under. Each keeper-core start advances a
durable boot epoch in `state/host-fence/keeper-boot-epoch` before it serves.
A grant records the boot that issued it, and resolve under a later boot is
terminal `denied_boot`. A guard whose lease was re-granted under the new boot
does not open a seal from the old one. The guard unwraps its key, checks
expiry on its own clock, opens the seal, and records `grant_ref` under one
fence lock, and a rebind's fence advance takes the same lock.

The seal is authenticated by static-static X25519 between the keeper and the
guard. Whoever holds the guard's private key can therefore make a blob that
guard opens. That is the guard itself, so this adds nothing to what the key
already allows. The key's secrecy inside the compartment is the boundary, as
for the channel. Expiry is a guard monotonic offset of at most 30 seconds from a
challenge the guard issued. The keeper's `expires_mono` is not that check.

## Consumption survives reload

Consumption and bootstrap-token use are appended to
`host-fence/authority-journal.jsonl`, a sibling of `authority/` and outside
the tree an adapter restores. The keeper epoch lives beside that journal in
`host-fence/keeper-epoch`, not only inside `grants.json`. Restoring
`authority/` (an older grant snapshot, or a scope file that still says
`used: false`) therefore does not revive a journaled grant or token, and
cannot roll the epoch back.

Issue is journaled with its operation id before the grant is saved. One
operation id yields one grant, so a restored `grants.json` cannot be used to
prepare the same approved use again. Every journal row is fsynced before the
call returns, so the consume is durable before the sealed answer leaves.

Use ttl is capped at 60 seconds.

## The compartment channel

Unix RPC is Noise KK, the wire Eggomi's keeper speaks
(`apps/desktop/src/keeper/cah/channel.ts`):
`Noise_KK_25519_ChaChaPoly_SHA256`, prologue `eggomi/cah-channel/v1`. The
workload is the initiator and knows the keeper's static key. The keeper
knows the workload's from its signed registry row. Each frame is a u16
big-endian length (1 to 65 535) and that many bytes. The workload sends
`0x01 ‖ KK message 1` (e, es, ss) with an empty payload. The keeper answers
`0x01 ‖ KK message 2` (e, ee, se), or refuses before any channel with
`0x00 ‖ ASCII code` and FIN. Each later frame is one transport message
(empty associated data, implicit counter nonce) carrying keeper.sock JSON:
`{"id","method","params"}` in, `{"id","result"}` or
`{"id","error":{"code","message"}}` out.

The keeper re-reads the peer's row, by instance, before every call. A row
that is gone is `denied_unadmitted`, a row whose incarnation changed
(including a move to another pid) is `denied_boot`, and
that refusal is the last frame before FIN. A frame that does not decrypt,
a zero length, or a malformed request closes the connection without a
reply. `SO_PEERPIDFD` (no `SO_PEERCRED` fallback) and a live pidfd still
gate the handshake. A process that holds a passed fd but not the registered
key cannot finish message 1.

## What this process split is

Non-keeper processes run in a user and mount namespace that hides
`state/authority`, `state/launcher` and other role directories, then bind-mounts only that
process's role material. `admission.json` is remounted read-only in that
namespace. After the first write the launcher rewrites the registry in
place under a write lock that readers share. A rename over the path would
detach the read-only bind in each confined namespace and leave the new
file writable there. Keeper stays unconfined because it owns the policy, the lab CA
key, and the journal.

Same-uid ptrace between the launcher and a stub is not additionally blocked.
keeper-core is unconfined and shares the launcher's uid, so in this lab
layout it could read the launcher's row key. The signature attributes rows
against every confined compartment, not against the keeper process.
Evidence for the fill remains E1 / `process_e2e`. It is not a confidentiality
claim and not `confidential_baremetal`.
