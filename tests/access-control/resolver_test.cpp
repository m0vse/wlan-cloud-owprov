#include "framework/UserAccessResolver.h"
#include <iostream>
#include <map>
#include <stdexcept>
using namespace OpenWifi::UserAccess;

struct Store {
    struct Entity { std::string parent; };
    struct Venue { std::string parent, entity; };
    struct Device { std::string subscriber, venue, entity; };
    std::map<std::string, Entity> entities;
    std::map<std::string, Venue> venues;
    std::map<std::string, Device> devices;
    template <class T> bool read(const std::map<std::string, T> &records, const std::string &id, T &record) {
        auto found = records.find(id);
        if (found == records.end()) return false;
        record = found->second;
        return true;
    }
    bool ReadEntity(const std::string &id, Entity &value) { return read(entities, id, value); }
    bool ReadVenue(const std::string &id, Venue &value) { return read(venues, id, value); }
    bool ReadDevice(const std::string &id, Device &value) { return read(devices, id, value); }
};

int main() {
    unsigned checks = 0;
    auto check = [&](bool value) {
        ++checks;
        if (!value) throw std::runtime_error("ownership check " + std::to_string(checks));
    };
    const Scope a{"entity", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"};
    const Scope b{"entity", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"};
    const Scope va{"venue", "11111111-1111-4111-8111-111111111111"};
    const Scope vb{"venue", "22222222-2222-4222-8222-222222222222"};
    const Scope child{"venue", "33333333-3333-4333-8333-333333333333"};
    Store store;
    store.entities = {{PlatformRoot.id, {}}, {a.id, {PlatformRoot.id}}, {b.id, {PlatformRoot.id}}};
    store.venues = {{va.id, {"", a.id}}, {vb.id, {"", b.id}}, {child.id, {va.id, ""}}};
    store.devices = {{"ap-a", {"", va.id, ""}}, {"ap-b", {"", vb.id, b.id}},
                     {"ap-child", {"", child.id, a.id}}, {"unassigned", {}},
                     {"entity-only", {"", "", a.id}}, {"subscriber", {"subscriber", va.id, a.id}}};
    Policy viewer{1, {{a, true, Preset("viewer")}}};
    auto allowed = [&](const std::string &serial) {
        return Allows(viewer, ResolveStoredDevice(store, serial), "devices.read");
    };
    check(allowed("ap-a"));
    check(allowed("ap-child"));
    check(allowed("entity-only"));
    check(!allowed("ap-b"));
    check(!allowed("unassigned"));
    check(!allowed("subscriber"));
    check(!allowed("unknown"));
    check(!ResolveStoredScope(store, PlatformRoot).ownershipResolved);
    store.devices["ap-b"].entity = a.id;
    check(!allowed("ap-b")); // Claimed inventory owner cannot override venue ownership.
    store.venues[child.id].entity = b.id;
    check(!allowed("ap-child"));
    store.venues[child.id].entity = "";
    store.venues[va.id].parent = child.id;
    check(!allowed("ap-a")); // Venue cycle.
    store.venues[va.id].parent = "";
    store.entities[a.id].parent = b.id;
    store.entities[b.id].parent = a.id;
    check(!allowed("ap-a")); // Entity cycle.
    store.entities[a.id].parent = PlatformRoot.id;
    store.entities[b.id].parent = PlatformRoot.id;
    store.entities.erase(PlatformRoot.id);
    check(!allowed("ap-a")); // Missing authoritative root is not an implicit root.
    store.entities[PlatformRoot.id] = {};
    store.venues[va.id].entity = "";
    check(!allowed("ap-a"));
    store.venues[va.id].entity = a.id;
    store.venues.erase(va.id);
    check(!allowed("ap-child"));
    std::cout << "PASS " << checks << " actual ownership-adapter checks\n";
}
