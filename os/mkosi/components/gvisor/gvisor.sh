# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash disable=SC2034
COMPONENT_NAME=gvisor
COMPONENT_CACHE_PATHS=(component-stages/gvisor)
COMPONENT_ROOTFS_TREES=(component-stages/gvisor)
COMPONENT_KERNEL_TREES=()

component_cache_key() {
    key_value "$GVISOR_RELEASE" "$GVISOR_BUNDLE_SHA512" "$GVISOR_RUNSC_SHA512" \
      "$GVISOR_SENTRY_SHA512" "$GVISOR_FDPARKING_SHA512" \
      "$GVISOR_PREWARMER_SHA512" "$GVISOR_CKPTGOFER_SHA512"
    key_file "$COMPONENT_PATH/gvisor-build.sh"
    key_packages bzip2
}

component_build() {
    "$COMPONENT_PATH/gvisor-build.sh" "$WORK/gvisor-build" \
      "$WORK/component-stages/gvisor"
}
