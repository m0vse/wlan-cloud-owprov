#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=$(mktemp "${TMPDIR:-/tmp}/venue-alert-policy.XXXXXX")
trap 'rm -f "$binary"' EXIT HUP INT TERM
"${CXX:-c++}" -std=c++17 -Wall -Wextra -Werror -pedantic -I"$root/src" "$root/src/VenueAlertPolicy.cpp" "$root/test_scripts/venue-alert-policy-test.cpp" -o "$binary"
"$binary"
