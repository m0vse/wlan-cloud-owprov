#pragma once
#include "framework/UserAccessPolicy.h"

namespace OpenWifi::UserAccess {
template <class Store> Resource ResolveStoredScope(Store &store, const Scope &scope) {
    std::string expectedEntity;
    return Resolve(scope, [&expectedEntity, &store](const Scope &current, Scope &parent) {
        if (current.type == "entity") {
            typename Store::Entity entity;
            if (!store.ReadEntity(current.id, entity)) return false;
            if (!expectedEntity.empty()) {
                if (current.id != expectedEntity) return false;
                expectedEntity.clear();
            }
            if (current == PlatformRoot) {
                if (!entity.parent.empty()) return false;
                parent = {};
            } else {
                if (entity.parent.empty()) return false;
                parent = {"entity", entity.parent};
            }
            return true;
        }
        if (current.type == "venue") {
            typename Store::Venue venue;
            if (!store.ReadVenue(current.id, venue)) return false;
            if (!venue.entity.empty()) {
                if (!expectedEntity.empty() && expectedEntity != venue.entity) return false;
                expectedEntity = venue.entity;
            }
            if (!venue.parent.empty()) {
                typename Store::Venue owner;
                if (!store.ReadVenue(venue.parent, owner)) return false;
                // A child cannot point into another customer's venue chain.
                if (!venue.entity.empty() && !owner.entity.empty() && venue.entity != owner.entity)
                    return false;
                parent = {"venue", venue.parent};
            } else {
                if (venue.entity.empty()) return false;
                parent = {"entity", venue.entity};
            }
            return true;
        }
        return false;
    });
}

template <class Store> Resource ResolveStoredDevice(Store &store, const std::string &serialNumber) {
    typename Store::Device device;
    if (serialNumber.empty() || !store.ReadDevice(serialNumber, device)) return {};
    if (!device.subscriber.empty()) return {}; // Subscriber ownership requires its own adapter.
    if (!device.venue.empty()) {
        auto resource = ResolveStoredScope(store, {"venue", device.venue});
        if (!device.entity.empty()) {
            const auto owner = std::find_if(resource.ancestors.begin(), resource.ancestors.end(),
                                            [](const Scope &node) { return node.type == "entity"; });
            if (owner == resource.ancestors.end() || owner->id != device.entity)
                resource.ownershipResolved = false;
        }
        return resource;
    }
    if (!device.entity.empty()) return ResolveStoredScope(store, {"entity", device.entity});
    return {}; // Unassigned APs remain platform-admin only.
}

} // namespace OpenWifi::UserAccess
