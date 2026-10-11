#pragma once
#include "StorageService.h"
#include "framework/UserAccessPolicyJSON.h"
#include "framework/UserAccessResolver.h"

namespace OpenWifi::UserAccess {
struct CanonicalOwnershipStore {
    using Entity = ProvObjects::Entity;
    using Venue = ProvObjects::Venue;
    using Device = ProvObjects::InventoryTag;
    bool ReadEntity(const std::string &id, Entity &value) {
        return StorageService()->EntityDB().GetRecord("id", id, value);
    }
    bool ReadVenue(const std::string &id, Venue &value) {
        return StorageService()->VenueDB().GetRecord("id", id, value);
    }
    bool ReadDevice(const std::string &serial, Device &value) {
        return StorageService()->InventoryDB().GetRecord("serialNumber", serial, value);
    }
};
inline Resource ResolveStoredScope(const Scope &scope) {
    CanonicalOwnershipStore store;
    return ResolveStoredScope(store, scope);
}
inline Resource ResolveStoredDevice(const std::string &serial) {
    CanonicalOwnershipStore store;
    auto normalized = serial;
    if (!Utils::NormalizeMac(normalized)) return {};
    return ResolveStoredDevice(store, normalized);
}
inline Resource ResolveOwner(const std::string &entity, const std::string &venue) {
    if (venue.empty()) return ResolveStoredScope({"entity", entity});
    auto resource = ResolveStoredScope({"venue", venue});
    if (!entity.empty()) {
        const auto owner = std::find_if(resource.ancestors.begin(), resource.ancestors.end(),
                                       [](const Scope &scope) { return scope.type == "entity"; });
        if (owner == resource.ancestors.end() || owner->id != entity) resource.ownershipResolved = false;
    }
    return resource;
}
inline bool AllowsUser(const SecurityObjects::UserInfo &user, const Resource &resource,
                       const std::string &capability) {
    if (user.id.empty() || user.suspended || user.blackListed) return false;
    if (user.userRole == SecurityObjects::ROOT) return KnownCapability(capability);
    Policy policy;
    if (!Parse(user.securityPolicy, policy)) return false;
    return Allows(policy, resource, capability);
}
} // namespace OpenWifi::UserAccess
