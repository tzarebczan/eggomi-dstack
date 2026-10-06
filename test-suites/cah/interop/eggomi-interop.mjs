// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Drives Eggomi's own keeper code (apps/desktop/src/keeper/cah/channel.ts,
// registry.ts and packages/noise) for the CAH interop tests. Run with
//
//   node --import ./ts-loader.mjs eggomi-interop.mjs <mode> ...
//
// Modes:
//   vectors                      print the shared vectors as JSON
//   verify-registry <doc> <pub>  readRegistry() on a stack-written registry
//   client <sock> <workload-private> <keeper-public> <calls-json> [go-file]
//                                openChannel() to a stack keeper, then calls
//   server <sock> <keeper-private> <workload-public> [stale-after]
//                                serveChannel() for one stack workload

import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createConnection, createServer } from "node:net";
import { join } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const root = process.env.CAH_EGGOMI_CHECKOUT;
const keeper = join(root, "apps/desktop/src/keeper");
const noise = await import(join(root, "packages/noise/src/noise.ts"));
const channel = await import(join(keeper, "cah/channel.ts"));
const registry = await import(join(keeper, "cah/registry.ts"));
const socketModule = await import(join(keeper, "socket.ts"));

const hex = (bytes) => Buffer.from(bytes).toString("hex");
const fromHex = (value) => new Uint8Array(Buffer.from(value, "hex"));
const EMPTY = new Uint8Array(0);

/** Fixed inputs. The stack test recomputes every output from these. */
const FIXED = {
  workload_static: "a1".repeat(32),
  keeper_static: "b2".repeat(32),
  workload_ephemeral: "c3".repeat(32),
  keeper_ephemeral: "d4".repeat(32),
  launcher_seed: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
  trust_domain: "lab.cah",
  tenant: "tenant-lab-1",
};

const ROWS = [
  {
    role: "omi-runner",
    instance_id: "omi-1",
    boot_id: "boot-omi-1-b",
    boot_generation: 3,
    boot_history: ["boot-omi-1", "boot-omi-1-b"],
    channel_public: hex(noise.generateKeyPair(fromHex(FIXED.workload_static)).publicKey),
    cert_fingerprint: null,
    pid: 4242,
    starttime: 987654321,
  },
  {
    role: "browser-guard",
    instance_id: 'inst-é "\\\n\u0001\u{1F600}',
    boot_id: "boot-\ud800-lone",
    boot_generation: 1,
    boot_history: ["boot-\ud800-lone"],
    channel_public: null,
    cert_fingerprint: "fp-\u007f/\t",
    pid: null,
    starttime: null,
  },
];

function launcherKeys(seedHex) {
  const der = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seedHex, "hex"),
  ]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  return { privateKey, publicRaw: Buffer.from(jwk.x, "base64url") };
}

function toRow(raw, doc) {
  return {
    trustDomain: doc.trust_domain,
    tenant: doc.tenant,
    role: raw.role,
    instanceId: raw.instance_id,
    bootId: raw.boot_id,
    bootGeneration: raw.boot_generation,
    bootHistory: raw.boot_history,
    channelPublic: raw.channel_public,
    certFingerprint: raw.cert_fingerprint,
    pid: raw.pid,
    starttime: raw.starttime,
  };
}

function channelVectors() {
  const initiator = new noise.KkInitiator({
    prologue: channel.CHANNEL_PROLOGUE,
    staticPrivateKey: fromHex(FIXED.workload_static),
    remoteStatic: noise.generateKeyPair(fromHex(FIXED.keeper_static)).publicKey,
    ephemeral: fromHex(FIXED.workload_ephemeral),
  });
  const responder = new noise.KkResponder({
    prologue: channel.CHANNEL_PROLOGUE,
    staticPrivateKey: fromHex(FIXED.keeper_static),
    remoteStatic: noise.generateKeyPair(fromHex(FIXED.workload_static)).publicKey,
    ephemeral: fromHex(FIXED.keeper_ephemeral),
  });
  const message1 = initiator.writeMessage1();
  responder.readMessage1(message1);
  const written = responder.writeMessage2();
  const read = initiator.readMessage2(written.message);
  const request = JSON.stringify({ id: 1, method: "health", params: {} });
  const response = JSON.stringify({ id: 1, result: { ok: true, role: "omi-runner" } });
  const requestCipher = read.transport.send.encryptWithAd(EMPTY, new TextEncoder().encode(request));
  const responseCipher = written.transport.send.encryptWithAd(
    EMPTY,
    new TextEncoder().encode(response),
  );
  return {
    prologue: Buffer.from(channel.CHANNEL_PROLOGUE).toString("utf8"),
    workload_public: hex(noise.generateKeyPair(fromHex(FIXED.workload_static)).publicKey),
    keeper_public: hex(noise.generateKeyPair(fromHex(FIXED.keeper_static)).publicKey),
    message1_frame: hex(channel.encodeFrame(Buffer.concat([Buffer.of(0x01), message1]))),
    message2_frame: hex(channel.encodeFrame(Buffer.concat([Buffer.of(0x01), written.message]))),
    handshake_hash: hex(read.transport.handshakeHash),
    request_json: request,
    request_frame: hex(channel.encodeFrame(requestCipher)),
    response_json: response,
    response_frame: hex(channel.encodeFrame(responseCipher)),
    refusal_code: "denied_unadmitted",
    refusal_frame: hex(
      channel.encodeFrame(Buffer.concat([Buffer.of(0x00), Buffer.from("denied_unadmitted")])),
    ),
  };
}

function rowVectors() {
  const { privateKey, publicRaw } = launcherKeys(FIXED.launcher_seed);
  const doc = { trust_domain: FIXED.trust_domain, tenant: FIXED.tenant };
  const cases = ROWS.map((raw) => {
    const message = registry.rowMessage(toRow(raw, doc));
    return {
      row: raw,
      message_hex: hex(message),
      launcher_sig: hex(sign(null, message, privateKey)),
    };
  });
  const signed = {
    schema_version: registry.REGISTRY_SCHEMA,
    ...doc,
    workloads: cases.map((c) => ({ ...c.row, launcher_sig: c.launcher_sig })),
  };
  const reading = registry.readRegistry(
    signed,
    [registry.launcherKey(publicRaw)],
    new registry.Watermarks(),
  );
  return {
    launcher_public: hex(publicRaw),
    cases,
    eggomi_accepts: reading.rows.map((r) => r.instanceId),
    eggomi_refuses: reading.refused.map((r) => r.reason),
  };
}

function vectors() {
  return {
    format: "cah-eggomi-interop/v1",
    about:
      "Generated by test-suites/cah/interop/eggomi-interop.mjs from Eggomi's channel.ts, " +
      "registry.ts and packages/noise. tests/test_interop.py recomputes every output in " +
      "Python and, with CAH_EGGOMI_CHECKOUT set, regenerates this file from Eggomi.",
    eggomi_commit: process.env.CAH_EGGOMI_COMMIT || "unknown",
    fixed: FIXED,
    channel: channelVectors(),
    rows: rowVectors(),
  };
}

function verifyRegistry(docPath, publicHex) {
  const doc = JSON.parse(readFileSync(docPath, "utf8"));
  const reading = registry.readRegistry(
    doc,
    [registry.launcherKey(fromHex(publicHex))],
    new registry.Watermarks(),
  );
  return {
    rows: reading.rows.map((r) => r.instanceId),
    refused: reading.refused.map((r) => ({ instance_id: r.instanceId, reason: r.reason })),
  };
}

async function client(sockPath, workloadPrivate, keeperPublic, callsJson, goFile) {
  if (goFile) {
    while (!existsSync(goFile)) await sleep(20);
  }
  const socket = createConnection(sockPath);
  await new Promise((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  let opened;
  try {
    opened = await channel.openChannel(socket, {
      staticPrivateKey: fromHex(workloadPrivate),
      keeperPublic: fromHex(keeperPublic),
    });
  } catch (error) {
    if (error instanceof channel.GateDenial) return { denial: error.code };
    return { closed: true };
  }
  const results = [];
  for (const [method, params] of JSON.parse(callsJson)) {
    try {
      results.push({ result: await opened.call(method, params) });
    } catch (error) {
      if (error instanceof socketModule.RpcError) results.push({ error: error.code });
      else {
        results.push({ closed: true });
        break;
      }
    }
  }
  opened.close();
  return { results };
}

function server(sockPath, keeperPrivate, workloadPublic, staleAfter) {
  let calls = 0;
  const limit = staleAfter === undefined ? Infinity : Number(staleAfter);
  const listener = createServer((socket) => {
    channel.serveChannel(socket, {
      staticPrivateKey: fromHex(keeperPrivate),
      identity: { channelPublic: fromHex(workloadPublic) },
      recheck: async () => (calls >= limit ? "denied_boot" : null),
      handle: async (method, params) => {
        calls += 1;
        if (method === "Refuse") throw new socketModule.RpcError("denied_role");
        return { method, echo: params };
      },
      log: () => {},
    });
  });
  listener.listen(sockPath, () => process.stdout.write("ready\n"));
  process.stdin.on("end", () => listener.close(() => process.exit(0)));
  process.stdin.resume();
}

const [mode, ...args] = process.argv.slice(2);
if (mode === "vectors") {
  process.stdout.write(`${JSON.stringify(vectors(), null, 2)}\n`);
} else if (mode === "verify-registry") {
  process.stdout.write(`${JSON.stringify(verifyRegistry(args[0], args[1]))}\n`);
} else if (mode === "client") {
  const out = await client(args[0], args[1], args[2], args[3], args[4]);
  process.stdout.write(`${JSON.stringify(out)}\n`);
} else if (mode === "server") {
  server(args[0], args[1], args[2], args[3]);
} else {
  process.stderr.write("usage: eggomi-interop.mjs vectors|verify-registry|client|server\n");
  process.exit(2);
}
