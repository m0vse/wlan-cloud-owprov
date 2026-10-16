#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
binary=$(mktemp "${TMPDIR:-/tmp}/venue-alert-integration.XXXXXX")
trap 'rm -f "$binary"' EXIT HUP INT TERM
if [ "${WITH_POCO:-0}" = 1 ]; then
    : "${POCO_PREFIX:?set POCO_PREFIX to the existing SDK install directory}"
    "${CXX:-c++}" -std=c++17 -Wall -Wextra -Werror -pedantic -DVENUE_ALERT_TEST_POCO -I"$root/src" -I"$POCO_PREFIX/include" "$root/src/VenueAlertPolicy.cpp" "$root/test_scripts/venue-alert-integration-test.cpp" -L"$POCO_PREFIX/lib" -Wl,-rpath,"$POCO_PREFIX/lib" -lPocoJSON -lPocoFoundation -o "$binary"
else
    "${CXX:-c++}" -std=c++17 -Wall -Wextra -Werror -pedantic -I"$root/src" "$root/src/VenueAlertPolicy.cpp" "$root/test_scripts/venue-alert-integration-test.cpp" -o "$binary"
fi
"$binary"
