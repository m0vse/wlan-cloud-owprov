# Reconnect configuration regression tests

Provisioning auto-discovery compares the generated effective configuration with
the gateway's stored configuration before assigning a new UUID. It skips the
push only if the online AP's reported UUID, stored device UUID and configuration
UUID agree, and no configuration is pending. Only the root configuration UUID
is excluded from the content comparison. Settings, credentials, nested UUIDs
and array ordering remain significant.

An unavailable or malformed snapshot, offline AP, failed/incomplete apply,
pending update or changed setting keeps the normal configuration-send path.
Manual pushes and scoped user authorization are unchanged. The Kafka connection
event UUID is not used: it identifies the connection, not the applied config.

Run inside the existing provisioning build SDK (no dependency updates):

```sh
g++ -std=c++20 -Isrc -I/vcpkg/installed/x64-linux/include \
  test_scripts/config_replay_test.cpp -o /tmp/config-replay-test
/tmp/config-replay-test
python3 test_scripts/config_replay_sdk_test.py
```

The first test covers semantic equality and active-version safeguards. The
second compiles the actual Configure method verbatim against real Poco JSON,
with fake HTTP boundaries, and verifies sends, preserved/new versions, retries,
manual pushes and forwarding of scoped authorization. Neither contacts APs.
Deployment qualification additionally runs the full native provisioning service
with SQLite, synthetic security/gateway peers and Kafka reconnect events in a
network-isolated container, including the existing venue-access regressions.
