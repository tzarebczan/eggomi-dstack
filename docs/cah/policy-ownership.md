# Policy ownership

`cah-keeper-policy/v1` is keeper-written. The profile file
`test-suites/cah/profiles/eggomi/keeper-policy.json` is an input to a test
double, not the live authority path.

`publish_revision` writes `authority/policy/<revision>.json` and points
`authority/policy/current` at that name. A revision id is immutable. A
different document for the same id is refused.

`PrepareUse` calls `load_current` on every request. The server does not
cache the document at startup. A requester echo that disagrees with the
loaded revision, including tenant, audience, field, origin, lease, and
recipient, is `denied_payload` and stores nothing.

`admit_scoped` does not import or read the policy directory. A scoped admit
still succeeds when that directory is absent.

The launcher in the fill demo calls `publish_revision` once, in the parent
process, to simulate the keeper write. It does not copy the fixture to
`authority/keeper-policy.json`.
