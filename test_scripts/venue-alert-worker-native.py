"""Actual PROV HTTP/SQLite/worker gate; synthetic loopback peers, no providers/APs.

Run inside the qualified native build image with networking disabled. Required:
AUDIT_PROV_BINARY, AUDIT_MOCK_BUS_BINARY. AUDIT_ROOT defaults to /audit.
This gate waits for real 30-second worker polls; it does not patch daemon clocks.
"""
import copy
import json
import os
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(os.environ.get("AUDIT_ROOT", "/audit"))
ROOT = "11111111-1111-4111-8111-111111111111"
USER = "22222222-2222-4222-8222-222222222222"
SERIALS = ["aabbcc000001", "aabbcc000002"]
state = {"policy": {"version": 1, "grants": []}, "gatewayReads": 0,
         "connected": False, "gatewayFailure": False, "radioFault": False,
         "staleHealth": False,
         "extraSerials": [],
         "deliveries": [], "blockDelivery": False}
release_delivery = threading.Event()
lock = threading.Lock()
checks = 0
process = None
bus = None
peer = None
gateway_peer = None
TLS = ssl._create_unverified_context()


def subject(root=False):
    return {"id": ROOT if root else USER, "userRole": "root" if root else "admin",
            "securityPolicy": "" if root else json.dumps(state["policy"]),
            "suspended": False, "blackListed": False, "securityPolicyChange": 1}


class Peer(BaseHTTPRequestHandler):
    def reply(self, payload, status=200):
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path.startswith("/api/v1/validateToken"):
            root = "synthetic-root" in self.path
            self.reply({"userInfo": subject(root), "tokenInfo": {
                "access_token": "synthetic-root" if root else "synthetic-user",
                "created": int(time.time()), "expires_in": 3600, "token_type": "Bearer"}})
        elif path.startswith("/api/v1/user/"):
            self.reply(subject(path.endswith(ROOT)))
        elif path == "/api/v1/devices":
            with lock:
                state["gatewayReads"] += 1
                failure, connected = state["gatewayFailure"], state["connected"]
                serials = SERIALS + state["extraSerials"]
            if failure:
                self.reply({"error": "synthetic collection unavailable"}, 503)
            else:
                self.reply({"devicesWithStatus": [
                    {"serialNumber": serial, "connected": connected} for serial in serials]})
        elif path.endswith("/healthchecks"):
            with lock:
                fault, stale = state["radioFault"], state["staleHealth"]
            active = [{"code": "radio_missing", "severity": "critical", "radio": "5G"}] if fault else []
            self.reply({"values": [{"recorded": int(time.time()) - (601 if stale else 0), "values": {
                "faults": {"active": active, "stale": False}}}]})
        elif path == "/api/v1/system":
            self.reply({"UI": "https://controller.example.invalid"})
        else:
            self.reply({}, 404)

    def do_POST(self):
        if urllib.parse.urlparse(self.path).path != "/api/v1/alertDelivery":
            self.reply({}, 404)
            return
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
        with lock:
            state["deliveries"].append(data)
            block = state["blockDelivery"]
            if data.get("channel") == "email" and not (BASE / "email-preview.html").exists():
                (BASE / "email-preview.html").write_text(data.get("html", ""))
        if block:
            release_delivery.wait(45)
        self.reply({"accepted": True, "providerId": "synthetic-accepted"})

    def log_message(self, *_args):
        pass


def request(method, path, body=None, root=True):
    req = urllib.request.Request("https://127.0.0.1:16005/api/v1/" + path,
        None if body is None else json.dumps(body).encode(),
        {"Authorization": "Bearer " + ("synthetic-root" if root else "synthetic-user"),
         "Content-Type": "application/json"}, method=method)
    try:
        with urllib.request.urlopen(req, context=TLS, timeout=8) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.load(error)
        except ValueError:
            return error.code, {}


def check(ok, label):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(label)
    print("PASS", checks, label, flush=True)


def wait_until(predicate, label, seconds=75):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        if process is not None and process.poll() is not None:
            raise RuntimeError("native PROV exited: " + label)
        time.sleep(.25)
    raise RuntimeError("timeout: " + label)


def deliveries():
    with lock:
        return copy.deepcopy(state["deliveries"])


def reads():
    with lock:
        return state["gatewayReads"]


def policy(enabled=False, email="alerts@example.org", sms=False, rules=None):
    return {"enabled": enabled, "emails": [email],
            "phones": ["+447700900123"] if sms else [],
            "rules": rules or [{"type": "down", "enabled": True, "delaySeconds": 0,
                "recoveryDelaySeconds": 0, "repeatSeconds": 0,
                "recovery": True, "email": True, "sms": sms}],
            "quietHours": {"enabled": False, "timezone": "Europe/London",
                "start": "22:00", "end": "08:00", "days": [1,2,3,4,5,6,7]},
            "muteUntil": 0, "groupBy": "venue", "groupWindowSeconds": 0}


def start():
    global process
    # The librdkafka mock broker retains dead group membership across forced
    # test-process exits. A fresh synthetic consumer group per daemon boot avoids
    # testing that mock-only rebalance limitation; SQLite/alert state is untouched.
    properties = BASE / "owprov.properties"
    group = "isolated-venue-alert-audit-" + str(time.monotonic_ns())
    properties.write_text("\n".join(
        line.split(" = ", 1)[0] + " = " + group
        if line.startswith(("openwifi.kafka.group.id = ", "openwifi.kafka.client.id = ")) else line
        for line in properties.read_text().splitlines()) + "\n")
    env = dict(os.environ, OWPROV_ROOT=str(BASE), OWPROV_CONFIG=str(BASE),
        LD_LIBRARY_PATH="/usr/local/lib:/vcpkg/installed/x64-linux/lib")
    process = subprocess.Popen([os.environ["AUDIT_PROV_BINARY"], "--file", str(BASE / "owprov.properties")],
        env=env, stdout=open(BASE / "prov.log", "a"), stderr=subprocess.STDOUT)
    last_result = {}
    def ready():
        try:
            status, answer = request("GET", "entity/0000-0000-0000")
            last_result.update(status=status, error=answer.get("ErrorCode"),
                               description=answer.get("ErrorDescription"))
            return status == 200
        except (OSError, urllib.error.URLError) as error:
            last_result.update(error=type(error).__name__)
            return False
    try:
        wait_until(ready, "authenticated native PROV ready", 65)
    except RuntimeError as error:
        raise RuntimeError(str(error) + "; last synthetic readiness result=" + json.dumps(last_result)) from error


def stop(force=False):
    global process
    if process is None:
        return
    if force:
        process.kill()
    else:
        process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
    process = None


def publish_service(kind, endpoint):
    bus.stdin.write(json.dumps({"id": 123456789 if kind == "owsec" else 123456790,
        "event": "join", "type": kind, "publicEndPoint": endpoint,
        "privateEndPoint": endpoint, "key": "synthetic-service-proof", "version": "audit"}) + "\n")
    bus.stdin.flush()


def setup():
    global peer, gateway_peer, bus
    BASE.mkdir(parents=True, exist_ok=True)
    for directory in ("certs", "data", "logs", "wwwassets"):
        (BASE / directory).mkdir(exist_ok=True)
    # This fixture directory must be fresh: retained alert state would invalidate
    # the initial disabled/no-outbound gate rather than being silently erased.
    check(not (BASE / "data/venue-alerts.json").exists(), "fresh synthetic alert state")
    (BASE / "data/registry.json").write_text(json.dumps({"deviceTypes": ["synthetic-ap"]}))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-passout", "pass:AuditSyntheticKey", "-keyout", str(BASE / "certs/key.pem"),
        "-out", str(BASE / "certs/cert.pem"), "-days", "1", "-subj", "/CN=localhost"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    peer = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    threading.Thread(target=peer.serve_forever, daemon=True).start()
    gateway_peer = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    threading.Thread(target=gateway_peer.serve_forever, daemon=True).start()
    bus = subprocess.Popen([os.environ["AUDIT_MOCK_BUS_BINARY"]], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=open(BASE / "bus.log", "w"), text=True)
    broker = bus.stdout.readline().strip()
    check(bool(broker), "isolated mock bus starts")
    endpoint = "http://127.0.0.1:" + str(peer.server_port)
    publish_service("owsec", endpoint)
    # The retained mock-bus rebroadcasts stored metadata every 400ms. Distinct
    # endpoints are mandatory: the actual directory is keyed by private URI.
    publish_service("owgw", "http://127.0.0.1:" + str(gateway_peer.server_port))
    props = []
    for prefix, port in [("openwifi.restapi", 16005), ("openwifi.internal.restapi", 17005)]:
        for key, value in {"address": "127.0.0.1", "port": port, "security": "relaxed",
            "rootca": str(BASE / "certs/cert.pem"), "cert": str(BASE / "certs/cert.pem"),
            "key": str(BASE / "certs/key.pem"), "key.password": "AuditSyntheticKey", "backlog": 30}.items():
            props.append(prefix + ".host.0." + key + " = " + str(value))
    props += ["openwifi.system.data = " + str(BASE / "data"),
        "openwifi.system.uri.private = https://127.0.0.1:17005",
        "openwifi.system.uri.public = https://127.0.0.1:16005",
        "openwifi.system.uri.ui = https://controller.example.invalid",
        "openwifi.security.restapi.disable = false",
        "openwifi.restapi.wwwassets = " + str(BASE / "wwwassets"),
        "openwifi.system.commandchannel = " + str(BASE / "command.socket"),
        "alb.enable = false", "openwifi.kafka.enable = true",
        "openwifi.kafka.group.id = isolated-venue-alert-audit",
        "openwifi.kafka.client.id = isolated-venue-alert-audit",
        "openwifi.kafka.brokerlist = " + broker, "storage.type = sqlite",
        "storage.type.sqlite.db = provisioning.db", "storage.type.sqlite.idletime = 120",
        "storage.type.sqlite.maxsessions = 16", "logging.type = null",
        "logging.path = " + str(BASE / "logs"), "logging.level = warning",
        "logging.asynch = false", "logging.websocket = false"]
    (BASE / "owprov.properties").write_text("\n".join(props) + "\n")
    start()


def run():
    setup()
    def create(kind, body):
        status, answer = request("POST", kind + "/0", body)
        check(status == 200, "synthetic " + kind + " create")
        return answer["id"]
    parent = create("entity", {"name": "Synthetic parent", "parent": "0000-0000-0000"})
    child = create("entity", {"name": "Synthetic child", "parent": parent})
    foreign = create("entity", {"name": "Foreign entity", "parent": "0000-0000-0000"})
    venue = create("venue", {"name": "Venue <&> audit", "entity": child})
    outsider = create("venue", {"name": "Foreign venue", "entity": foreign})
    alert_path = "venue/" + venue + "?alerts=true"
    for index, serial in enumerate(SERIALS):
        status, _answer = request("POST", "inventory/" + serial, {"serialNumber": serial,
            "name": "AP <script>" if index == 0 else "AP & second", "venue": venue,
            "deviceType": "synthetic-ap", "devClass": "any", "platform": "AP"})
        check(status == 200, "synthetic actual SQLite inventory create")
    wait_until(lambda: request("GET", alert_path)[1].get("available") is True,
               "new alert service available")
    baseline = reads()
    time.sleep(31)
    check(reads() == baseline and not deliveries(), "disabled worker performs no gateway reads or sends")
    for entity, recipient in [(parent, "parent@example.org"), (child, "child@example.org")]:
        status, answer = request("PUT", "entity/" + entity + "?alerts=true", policy(email=recipient))
        check(status == 200, "entity alert settings save" +
              (" status=" + str(status) + " body=" + json.dumps(answer) if status != 200 else ""))
    answer = request("GET", alert_path)[1]
    check(answer["inherited"] and answer["settings"]["emails"] == ["child@example.org"],
          "nearest entity defaults inherited")
    check(request("PUT", alert_path, policy(email="venue@example.org"))[0] == 200,
          "venue override saves")
    answer = request("GET", alert_path)[1]
    check(answer["configured"] and not answer["inherited"] and
          answer["settings"]["emails"] == ["venue@example.org"], "venue override wins")
    check(request("PUT", alert_path, {"inherit": True})[0] == 200, "venue resets to inheritance")
    check(request("GET", alert_path)[1]["settings"]["emails"] == ["child@example.org"],
          "reset returns nearest entity policy")
    state["policy"] = {"version": 1, "grants": [{"scopeType": "venue", "scopeId": venue,
        "includeDescendants": False, "capabilities": ["devices.read"]}]}
    check(request("GET", alert_path, root=False)[0] == 200, "scoped venue read allowed")
    check(request("PUT", alert_path, policy(), root=False)[0] == 403, "read-only scoped write denied")
    check(request("GET", "venue/" + outsider + "?alerts=true", root=False)[0] == 403,
          "foreign venue alert read denied")
    check(request("GET", "entity/" + child + "?alerts=true", root=False)[0] == 403,
          "venue grant does not reveal ancestor policy")
    answer = request("GET", alert_path, root=False)[1]
    check("id" not in answer.get("sourceScope", {}), "inherited source id hidden without ancestor grant")
    state["policy"]["grants"][0]["capabilities"].append("resources.write")
    status, answer = request("PUT", alert_path, policy(), root=False)
    check(status == 200, "scoped venue edit allowed" +
          (" status=" + str(status) + " body=" + json.dumps(answer) if status != 200 else ""))
    check(request("PUT", alert_path + "&rebootAllDevices=true", policy(), root=False)[0] == 403,
          "mixed command query does not inherit alert write permission")
    check(request("PUT", "venue/" + venue, {"name": "Unauthorized rename"}, root=False)[0] == 403,
          "alert writer cannot perform ordinary venue updates")
    check(request("PUT", "entity/" + child + "?alerts=true", policy(), root=False)[0] == 403,
          "venue alert writer cannot update ancestor entity defaults")
    state["policy"]["grants"][0]["capabilities"].remove("resources.write")
    check(request("PUT", alert_path, policy(), root=False)[0] == 403,
          "write revocation enforced immediately for existing token")
    check(request("GET", alert_path, root=False)[0] == 200,
          "write revocation preserves explicitly granted venue reading")
    state["policy"]["grants"][0]["capabilities"].append("resources.write")
    check(request("PUT", alert_path, policy(), root=False)[0] == 200,
          "restored write grant works without changing the existing token")
    check(request("PUT", "venue/" + outsider + "?alerts=true", policy(), root=False)[0] == 403,
          "foreign venue edit denied")
    invalid = policy()
    invalid["webhook"] = "https://example.invalid"
    check(request("PUT", alert_path, invalid)[0] == 400, "unknown policy field rejected over actual API")
    check(request("PUT", alert_path, policy(True, sms=True))[0] == 200, "enable email and SMS alert rules")
    wait_until(lambda: len(deliveries()) >= 3, "real worker grouped fault delivery")
    messages = deliveries()
    email = [message for message in messages if message["channel"] == "email"]
    sms = [message for message in messages if message["channel"] == "sms"]
    check(len(messages) == 3 and len(email) == 1 and len(sms) == 2,
          "two AP faults produce one grouped email and one SMS per AP")
    check(all(serial in email[0]["text"] for serial in SERIALS), "grouped email contains both APs")
    check("&lt;script&gt;" in email[0]["html"] and "AP <script>" not in email[0]["html"] and
          "Venue &lt;&amp;&gt; audit" in email[0]["html"], "actual grouped HTML escapes inventory names")
    check(all("html" not in message and "OpenWiFi:" in message["text"] for message in sms),
          "SMS remains simple text")
    history = request("GET", alert_path, root=False)[1]["events"]
    check(len(history) == 4 and all(event["status"] == "accepted" for event in history),
          "live history shows latest accepted delivery state without reload")
    check(len({event["id"] for event in history}) == 4 and
          all("scopes" not in event and event["device"] in SERIALS for event in history),
          "history deduplicates delivery ids and excludes internal scope metadata")
    time.sleep(31)
    check(len(deliveries()) == 3, "no repeats when repeatSeconds is zero")
    stop()
    start()
    time.sleep(34)
    check(len(deliveries()) == 3, "accepted faults do not resend across actual daemon restart")
    with lock:
        state["connected"] = True
    wait_until(lambda: len(deliveries()) >= 6, "actual accepted-fault recovery delivery")
    check(len(deliveries()) == 6 and all("AP offline cleared" in m["text"]
          for m in deliveries()[3:]), "recovery is grouped and only follows accepted faults")
    health_rules = [{"type": kind, "enabled": True, "delaySeconds": 0,
        "recoveryDelaySeconds": 0, "repeatSeconds": 0, "recovery": True,
        "email": True, "sms": False} for kind in ("critical", "radio")]
    with lock:
        state["radioFault"] = True
    before_health = len(deliveries())
    check(request("PUT", alert_path, policy(True, rules=health_rules))[0] == 200,
          "enable actual health/radio worker rules")
    wait_until(lambda: len(deliveries()) > before_health, "critical/radio health record delivery")
    health_message = deliveries()[before_health:]
    check(len(health_message) == 1 and "Critical fault" in health_message[0]["text"] and
          "Radio fault" in health_message[0]["text"], "health critical/radio events grouped in one email")
    with lock:
        state["radioFault"] = False
        state["staleHealth"] = True
    time.sleep(34)
    check(len(deliveries()) == before_health + 1, "stale health cannot generate recovery")
    with lock:
        state["staleHealth"] = False
    wait_until(lambda: len(deliveries()) > before_health + 1, "fresh health recovery delivery")
    check(len(deliveries()) == before_health + 2 and
          "Critical fault cleared" in deliveries()[-1]["text"] and
          "Radio fault cleared" in deliveries()[-1]["text"],
          "fresh healthy record recovers accepted health/radio alerts")
    with lock:
        state["gatewayFailure"] = True
    before = len(deliveries())
    time.sleep(34)
    check(len(deliveries()) == before, "gateway collection failure infers neither down nor recovery")
    with lock:
        state["gatewayFailure"] = False
    # A crash after persisted dispatch reservation must not blindly retry an
    # accepted-or-unknown provider call after restart.
    check(request("PUT", alert_path, policy(True))[0] == 200, "prepare in-flight restart gate")
    with lock:
        state["connected"] = False
        state["blockDelivery"] = True
    wait_until(lambda: len(deliveries()) > before, "synthetic in-flight provider call")
    persisted = json.loads((BASE / "data/venue-alerts.json").read_text())
    check(any(item["dispatching"] for item in persisted["queue"]), "dispatch reservation durable before provider call")
    interrupted_ids = {item["delivery"]["id"] for item in persisted["queue"] if item["dispatching"]}
    accepted_ids = {event["id"] for event in persisted["events"] if event["status"] == "accepted"}
    flight_count = len(deliveries())
    stop(force=True)
    release_delivery.set()
    with lock:
        state["blockDelivery"] = False
    start()
    time.sleep(34)
    check(len(deliveries()) == flight_count, "in-flight restart conservatively held without duplicate sends")
    history = {event["id"]: event for event in request("GET", alert_path)[1]["events"]}
    check(interrupted_ids and all(history[identity]["status"] == "unknown" for identity in interrupted_ids),
          "interrupted delivery history reports unknown rather than permanent dispatching")
    check(accepted_ids and all(history[identity]["status"] == "accepted" for identity in accepted_ids),
          "restart preserves previously accepted delivery history")
    # Real pending-delay restoration: collect at least two polls, restart, and
    # inspect the worker's actual durable elapsed value rather than a mock clock.
    delayed = policy(True)
    delayed["rules"][0]["delaySeconds"] = 120
    check(request("PUT", alert_path, delayed)[0] == 200, "prepare sustained-delay restart gate")
    def elapsed():
        try:
            document = json.loads((BASE / "data/venue-alerts.json").read_text())
            return [alert["elapsed"] for alert in document["engine"]["alerts"]
                    if alert["serial"] in SERIALS and alert["type"] == "down"]
        except (FileNotFoundError, ValueError, KeyError):
            return []
    wait_until(lambda: elapsed() and min(elapsed()) >= 25, "pending fault elapsed observed by actual worker", 95)
    delay_count = len(deliveries())
    stop(force=True)
    start()
    wait_until(lambda: elapsed() and max(elapsed()) < 25, "restart clears unobserved delay continuity", 65)
    check(len(deliveries()) == delay_count, "restart does not turn downtime into immediate delayed alert")
    # Disable sends and confirm the durable policy itself survives restart.
    check(request("PUT", alert_path, policy(False))[0] == 200, "disable alert delivery")
    direct_serials = ["aabbcc000003", "aabbcc000004"]
    for serial, entity in zip(direct_serials, (parent, foreign)):
        check(request("POST", "inventory/" + serial, {"serialNumber": serial,
            "name": "Direct entity AP", "entity": entity, "deviceType": "synthetic-ap",
            "devClass": "any", "platform": "AP"})[0] == 200,
            "direct entity-owned AP fixture")
    with lock:
        state["extraSerials"] = direct_serials
    direct_count = len(deliveries())
    for entity in (parent, foreign):
        check(request("PUT", "entity/" + entity + "?alerts=true",
              policy(True, email="direct@example.org"))[0] == 200,
              "direct entity alert policy enabled")
    wait_until(lambda: len(deliveries()) >= direct_count + 2, "direct entity fault deliveries")
    direct_messages = deliveries()[direct_count:]
    check(len(direct_messages) == 2 and all(message["recipient"] == "direct@example.org"
          for message in direct_messages), "same-recipient direct APs retain separate entity groups")
    check(all(sum(serial in message["text"] for serial in direct_serials) == 1
          for message in direct_messages), "direct entity groups do not leak across entities")
    history = request("GET", alert_path, root=False)[1]["events"]
    check(all(event["device"] in SERIALS for event in history),
          "venue-scoped history excludes unrelated direct entity APs")
    for entity in (parent, foreign):
        check(request("PUT", "entity/" + entity + "?alerts=true", policy(False))[0] == 200,
              "disable synthetic direct entity policy")
    baseline = reads()
    time.sleep(31)
    check(reads() == baseline, "all-disabled configuration stops gateway polling")
    stop()
    start()
    answer = request("GET", alert_path)[1]
    check(answer["available"] and answer["configured"] and not answer["settings"]["enabled"],
          "disabled venue settings survive native restart")
    print("PASS", checks, "native venue alert HTTP/SQLite/auth/inheritance/worker/grouping/restart controls")


def cleanup():
    release_delivery.set()
    stop()
    if bus is not None:
        bus.terminate()
        try:
            bus.wait(timeout=5)
        except subprocess.TimeoutExpired:
            bus.kill()
            bus.wait()
    if peer is not None:
        peer.shutdown()
    if gateway_peer is not None:
        gateway_peer.shutdown()


if __name__ == "__main__":
    try:
        run()
    finally:
        cleanup()
