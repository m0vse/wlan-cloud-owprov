"""Actual native HTTP regression for the stored provisioning-root sentinel.

Run in the isolated runtime-test image with venue-alert-worker-native.py beside
this file. All policies are disabled; no provider/AP requests are performed.
"""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("venue_alert_gate",
    Path(__file__).with_name("venue-alert-worker-native.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def run():
    gate.setup()
    root_path = "entity/0000-0000-0000?alerts=true"
    status, answer = gate.request("GET", root_path)
    gate.check(status == 200 and answer["available"] and not answer["configured"],
        "platform administrator reads existing root alert defaults")
    settings = gate.policy(email="platform@example.org")
    status, answer = gate.request("PUT", root_path, settings)
    gate.check(status == 200 and answer["configured"] and not answer["inherited"] and
        answer["settings"]["emails"] == ["platform@example.org"],
        "platform administrator saves disabled root alert defaults")
    status, entity = gate.request("POST", "entity/0",
        {"name": "Root regression site", "parent": "0000-0000-0000"})
    gate.check(status == 200, "synthetic descendant entity create")
    status, venue = gate.request("POST", "venue/0",
        {"name": "Root regression venue", "entity": entity["id"]})
    gate.check(status == 200, "synthetic descendant venue create")
    venue_path = "venue/" + venue["id"] + "?alerts=true"
    for path in ("entity/" + entity["id"] + "?alerts=true", venue_path):
        status, answer = gate.request("GET", path)
        gate.check(status == 200 and answer["inherited"] and
            answer["settings"]["emails"] == ["platform@example.org"] and
            answer["sourceScope"]["id"] == "0000-0000-0000",
            "descendant inherits real stored root policy")
    gate.state["policy"] = {"version": 1, "grants": [{"scopeType": "venue",
        "scopeId": venue["id"], "includeDescendants": False,
        "capabilities": ["devices.read", "resources.write"]}]}
    status, answer = gate.request("GET", venue_path, root=False)
    gate.check(status == 200 and answer["inherited"] and "id" not in answer["sourceScope"],
        "venue reader receives inherited defaults without global source identifier")
    gate.check(gate.request("GET", root_path, root=False)[0] == 403,
        "venue grant does not authorize direct root alert reads")
    gate.check(gate.request("PUT", root_path, settings, root=False)[0] == 403,
        "venue writer cannot change global root alert defaults")
    gate.check(gate.request("PUT", venue_path, gate.policy(email="venue@example.org"),
        root=False)[0] == 200, "explicit scoped venue edit remains functional")
    gate.check(gate.request("PUT", venue_path, {"inherit": True}, root=False)[0] == 200,
        "explicit scoped venue reset remains functional")
    gate.state["policy"] = {"version": 1, "grants": [{"scopeType": "entity",
        "scopeId": "0000-0000-0000", "includeDescendants": True,
        "capabilities": ["devices.read", "resources.write"]}]}
    gate.check(gate.request("GET", root_path, root=False)[0] == 403,
        "sentinel remains invalid as a fabricated tenant grant")
    gate.check(gate.request("PUT", root_path, settings, root=False)[0] == 403,
        "fabricated sentinel grant cannot write global defaults")
    status, answer = gate.request("PUT", root_path, {"inherit": True})
    gate.check(status == 200 and not answer["configured"] and not answer["inherited"] and
        not answer["settings"]["enabled"], "root reset removes only configured root defaults")
    gate.check(gate.request("GET", "entity/00000000-0000-4000-8000-000000000000?alerts=true")[0] == 404,
        "missing ordinary entity is not mistaken for root")
    gate.check(gate.request("GET", "venue/0000-0000-0000?alerts=true")[0] == 404,
        "root special case does not apply to venues")
    print("PASS", gate.checks, "native stored-root alert adapter controls", flush=True)


if __name__ == "__main__":
    try:
        run()
    finally:
        gate.cleanup()
