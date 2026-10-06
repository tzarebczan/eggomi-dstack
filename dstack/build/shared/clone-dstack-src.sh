#!/bin/bash

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Clone DSTACK_SRC_URL and check out DSTACK_REV into ./repo.
#
# A private mirror cannot clone itself anonymously. When BuildKit mounts a
# secret named github_token, that token is sent only as an HTTP header for
# this process. It is not written into the remote URL, the image, or argv.
# Public clones leave the secret unset and stay anonymous.

set -euo pipefail

if [ -z "${DSTACK_SRC_URL:-}" ] || [ -z "${DSTACK_REV:-}" ]; then
    echo "DSTACK_SRC_URL and DSTACK_REV are required" >&2
    exit 1
fi

export GIT_TERMINAL_PROMPT=0

secret=/run/secrets/github_token
if [ -s "$secret" ]; then
    token=$(tr -d '[:space:]' <"$secret")
    if [ -n "$token" ]; then
        export GIT_CONFIG_COUNT=1
        export GIT_CONFIG_KEY_0=http.extraheader
        export GIT_CONFIG_VALUE_0="AUTHORIZATION: bearer ${token}"
    fi
    unset token
fi

git clone "${DSTACK_SRC_URL}" repo
unset GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0
git -C repo checkout "${DSTACK_REV}"
