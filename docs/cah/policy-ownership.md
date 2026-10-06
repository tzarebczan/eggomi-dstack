# Policy ownership

`cah-keeper-policy/v1` is keeper-written. The profile file
`test-suites/cah/profiles/eggomi/keeper-policy.json` is an input to a test
double, not the live authority path.

`publish_revision` writes `authority/policy/<revision>.json` and points
`authority/policy/current` at that name. A revision id is immutable. A
different document for the same id is refused. `current` moves only to a
revision this call creates. Pointing it back at an older revision is
refused.

`PrepareUse` calls `load_current` on every request. The server does not
cache the document at startup. A requester echo that disagrees with the
loaded revision, including tenant, audience, field, origin, lease, and
recipient, is `denied_payload` and stores nothing. Each operation names
its `requester_instance_id`. A `PrepareUse` from any other admitted
requester is `denied_payload` and does not spend the operation. An
operation id yields one grant. A second
`PrepareUse` for it is `denied_payload` and stores nothing, also after
`authority/` is restored, because issue is journaled under `host-fence/`.
A retry needs a new operation id in a new revision. `ResolveUseGrant` does
not reload policy. A newer revision does not revoke an outstanding grant
inside its ttl. The next `PrepareUse` sees the new revision, and the
outstanding grant expires with that ttl.

`admit_scoped` does not import or read the policy directory. A scoped admit
still succeeds when that directory is absent.

The keeper publishes immutable revisions. In the lab demo the launcher is
that test double and calls `publish_revision` once, in the parent process,
with the profile fixture. It does not copy the fixture to
`authority/keeper-policy.json`.
