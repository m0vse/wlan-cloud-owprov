#pragma once
#include "StorageService.h"
#include "framework/UserAccessPolicyJSON.h"
#include "framework/UserAccessResolver.h"
#include "framework/OpenAPIRequests.h"
#include "framework/MicroServiceNames.h"
#include "framework/UserAccessClient.h"

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
inline bool ReadCurrentUser(const std::string &id, SecurityObjects::UserInfo &user) {
    if (!ValidScope({"entity",id})) return false;
    OpenAPIRequestGet request(uSERVICE_SECURITY,"/api/v1/user/"+id,{},3000);
    Poco::JSON::Object::Ptr response;
    if (request.Do(response)!=Poco::Net::HTTPServerResponse::HTTP_OK || !response ||
        !response->has("userRole") || !response->has("suspended") || !response->has("blackListed") ||
        !response->has("securityPolicy") || !response->get("userRole").isString() ||
        !response->get("securityPolicy").isString() ||
        response->get("suspended").type()!=typeid(bool) || response->get("blackListed").type()!=typeid(bool)) return false;
    user.userRole=SecurityObjects::UNKNOWN;
    return user.from_json(response) && user.id==id && user.userRole!=SecurityObjects::UNKNOWN &&
           !user.suspended && !user.blackListed;
}
inline Resource ResolveStoredObject(const std::string &kind,const std::string &id) {
    if(kind=="inventory")return ResolveStoredDevice(id);
    if(kind=="entity"||kind=="venue")return ResolveStoredScope({kind,id});
    if(kind=="configuration") {
        ProvObjects::DeviceConfiguration object;
        if(StorageService()->ConfigurationDB().GetRecord("id",id,object)&&object.subscriber.empty())
            return ResolveOwner(object.entity,object.venue);
    } else if(kind=="variable") {
        ProvObjects::VariableBlock object;
        if(StorageService()->VariablesDB().GetRecord("id",id,object)&&object.subscriber.empty()&&object.inventory.empty())
            return ResolveOwner(object.entity,object.venue);
    } else if(kind=="map") {
        ProvObjects::Map object;
        if(StorageService()->MapDB().GetRecord("id",id,object))return ResolveOwner(object.entity,object.venue);
    } else if(kind=="contact") {
        ProvObjects::Contact object;
        if(StorageService()->ContactDB().GetRecord("id",id,object))return ResolveStoredScope({"entity",object.entity});
    } else if(kind=="location") {
        ProvObjects::Location object;
        if(StorageService()->LocationDB().GetRecord("id",id,object))return ResolveStoredScope({"entity",object.entity});
    }
    return {};
}
inline Decision CheckVenueLocationReference(const SecurityObjects::UserInfo &actor,
        const std::string &locationId,const std::string &venueId,const std::string &snapshotEntity={}) {
    if(actor.id.empty()||actor.suspended||actor.blackListed||!ValidScope({"venue",venueId}))return {};
    SecurityObjects::UserInfo current;
    if(!ReadCurrentUser(actor.id,current))return {};
    ProvObjects::Venue venue;ProvObjects::Location location;
    if(!StorageService()->VenueDB().GetRecord("id",venueId,venue)||venue.location!=locationId||
       !StorageService()->LocationDB().GetRecord("id",locationId,location)||location.entity.empty()||
       (!snapshotEntity.empty()&&location.entity!=snapshotEntity))return {};
    auto resource=ResolveStoredScope({"venue",venueId});
    const auto owner=std::find_if(resource.ancestors.begin(),resource.ancestors.end(),
                                [](const Scope &scope){return scope.type=="entity";});
    if(owner==resource.ancestors.end()||owner->id!=location.entity)return {};
    return {AllowsUser(current,resource,"devices.read"),AllowsUser(current,resource,"secrets.read")};
}
} // namespace OpenWifi::UserAccess
