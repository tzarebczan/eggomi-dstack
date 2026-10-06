# Measurement schema pin

`measurement.schema.json` is a byte copy of WSE 1.0
`schemas/measurement.schema.json`.

SHA-256: `68d13090ca64469b258790e850e28f747f2100f06d9f807d80cb314d95634003`

WS1 revision 1 moves measurement contracts under `contracts/` and was not
attached to this change. The CAH emitter still validates against this pin.
Replace the file when the new bundle is pinned; do not treat a missing
sample as zero in either revision.
