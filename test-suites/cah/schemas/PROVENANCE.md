# Measurement schema pin

`measurement.schema.json` is a byte copy of WSE 1.0
`schemas/measurement.schema.json`.

SHA-256: `68d13090ca64469b258790e850e28f747f2100f06d9f807d80cb314d95634003`

WS1 revision 1 `contracts/metrics.json` is vendored at
`test-suites/cah/contracts/ws1/metrics.json`.

SHA-256: `ab065b7d1422713c17e2a906df4253cd3cf6c82b0e93cb3f21c83506329a3ce5`

The CAH emitter still validates the WSE 1.0 pin above. A mapped migration
onto the WS1 metric names is deferred. Do not treat a missing sample as zero
in either revision. `sum_present` returns null when any selected row is
unavailable and refuses to add one metric across scopes or roles.
