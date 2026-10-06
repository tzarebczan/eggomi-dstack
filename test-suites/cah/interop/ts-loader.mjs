// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// `node --import ./ts-loader.mjs`: registers ts-hooks.mjs, which loads
// Eggomi's TypeScript sources unchanged.
//
//   CAH_EGGOMI_CHECKOUT      an Eggomi checkout (or a `git archive` of one)
//   CAH_EGGOMI_NODE_MODULES  a `node_modules` directory holding
//                            @noble/ciphers, @noble/curves, @noble/hashes
//                            and typescript (default: <checkout>/node_modules)

import * as nodeModule from "node:module";
import { join } from "node:path";
import * as hooks from "./ts-hooks.mjs";

const checkout = process.env.CAH_EGGOMI_CHECKOUT;
if (!checkout) throw new Error("CAH_EGGOMI_CHECKOUT is not set");
const nodeModules = process.env.CAH_EGGOMI_NODE_MODULES || join(checkout, "node_modules");

const data = { checkout, nodeModules };
if (typeof nodeModule.registerHooks === "function") {
  hooks.initialize(data);
  nodeModule.registerHooks({ resolve: hooks.resolve, load: hooks.load });
} else {
  nodeModule.register(new URL("./ts-hooks.mjs", import.meta.url), { data });
}
