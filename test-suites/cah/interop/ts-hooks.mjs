// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Module hooks for Eggomi's keeper sources. They use extensionless relative
// imports, the workspace name `@eggomi/noise`, and TypeScript parameter
// properties, none of which Node's built-in type stripping handles. These
// hooks map the names and transpile each `.ts` file with the `typescript`
// package from CAH_EGGOMI_NODE_MODULES. The hooks are synchronous, so they
// serve both module.registerHooks() and module.register().

import { readFileSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

let config = null;
let ts = null;

export function initialize(data) {
  config = data;
}

function typescript() {
  if (ts === null) {
    const require = createRequire(join(config.nodeModules, "noop.cjs"));
    ts = require(join(config.nodeModules, "typescript"));
  }
  return ts;
}

function isFile(path) {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

export function resolve(specifier, context, nextResolve) {
  if (specifier === "@eggomi/noise") {
    const url = pathToFileURL(join(config.checkout, "packages/noise/src/index.ts")).href;
    return { url, shortCircuit: true };
  }
  const parent = context.parentURL ?? "";
  if ((specifier.startsWith("./") || specifier.startsWith("../")) && parent.endsWith(".ts")) {
    const base = fileURLToPath(new URL(specifier, parent));
    for (const candidate of [`${base}.ts`, base, join(base, "index.ts")]) {
      if (isFile(candidate)) return { url: pathToFileURL(candidate).href, shortCircuit: true };
    }
  }
  if (specifier.startsWith("@noble/") || specifier === "typescript") {
    // Resolve as if imported from a file beside the node_modules directory.
    const anchor = pathToFileURL(join(config.nodeModules, "..", "cah-interop.mjs")).href;
    return nextResolve(specifier, { ...context, parentURL: anchor });
  }
  return nextResolve(specifier, context);
}

export function load(url, context, nextLoad) {
  if (!url.startsWith("file:") || !url.endsWith(".ts")) return nextLoad(url, context);
  const path = fileURLToPath(url);
  const out = typescript().transpileModule(readFileSync(path, "utf8"), {
    compilerOptions: {
      module: typescript().ModuleKind.ESNext,
      target: typescript().ScriptTarget.ES2022,
      useDefineForClassFields: true,
    },
    fileName: path,
  });
  return { format: "module", source: out.outputText, shortCircuit: true };
}
