#include "RESTAPI_access_check_handler.h"
#include "UserAccess.h"
#include "framework/OpenAPIRequests.h"
#include "framework/MicroServiceNames.h"

namespace OpenWifi {
void RESTAPI_access_check_handler::DoPost() {
    // Public callers can check their own identity. The internal router requires
    // an authenticated service key before checking a forwarded stable user ID.
    const bool serviceRequest = Internal_ && Request->has("X-INTERNAL-NAME");
    if (Internal_ && !serviceRequest)
        return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
    if (!ParsedBody_ || !ParsedBody_->has("userId") || !ParsedBody_->has("capability") ||
        !ParsedBody_->get("userId").isString() || !ParsedBody_->get("capability").isString())
        return BadRequest(RESTAPI::Errors::InvalidJSONDocument);
    const auto userId = ParsedBody_->getValue<std::string>("userId");
    if (!serviceRequest && UserInfo_.userinfo.userRole != SecurityObjects::ROOT &&
        userId != UserInfo_.userinfo.id) return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
    const auto capability = ParsedBody_->getValue<std::string>("capability");
    if (!UserAccess::ValidScope({"entity", userId}) || !UserAccess::KnownCapability(capability))
        return BadRequest(RESTAPI::Errors::InvalidJSONDocument);
    // Services forward the authenticated user's stable ID, not a policy or an
    // entity supplied by the browser. Retrieve current policy from owsec.
    OpenAPIRequestGet request(uSERVICE_SECURITY, "/api/v1/user/" + userId, {}, 3000);
    Poco::JSON::Object::Ptr response;
    if (request.Do(response) != Poco::Net::HTTPServerResponse::HTTP_OK || !response ||
        !response->has("userRole") || !response->has("suspended") || !response->has("blackListed") ||
        !response->has("securityPolicy") || !response->get("userRole").isString() ||
        !response->get("securityPolicy").isString() ||
        response->get("suspended").type() != typeid(bool) ||
        response->get("blackListed").type() != typeid(bool))
        return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
    SecurityObjects::UserInfo user;
    user.userRole = SecurityObjects::UNKNOWN;
    if (!user.from_json(response) || user.id != userId || user.userRole == SecurityObjects::UNKNOWN)
        return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
    if (user.suspended || user.blackListed) return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
    UserAccess::Resource resource;
    if (ParsedBody_->has("listDevices") && ParsedBody_->get("listDevices").type() != typeid(bool))
        return BadRequest(RESTAPI::Errors::InvalidJSONDocument);
    if (ParsedBody_->optValue<bool>("listDevices", false)) {
        if (capability != "clients.read") return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
        Poco::JSON::Array devices;
        for (uint64_t offset = 0;; offset += 500) {
            InventoryDB::RecordVec page;
            if (!StorageService()->InventoryDB().GetRecords(offset, 500, page, "", " ORDER BY serialNumber ASC "))
                return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
            for (const auto &inventory : page) {
                const auto scope = UserAccess::ResolveStoredDevice(inventory.serialNumber);
                if (!UserAccess::AllowsUser(user, scope, capability)) continue;
                if (devices.size() >= 5000) return UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
                Poco::JSON::Object device;
                device.set("serialNumber", inventory.serialNumber);
                device.set("entity", inventory.entity); device.set("venue", inventory.venue);
                devices.add(device);
            }
            if (page.size() < 500) break;
        }
        Poco::JSON::Object answer; answer.set("devices", devices);
        answer.set("policyRevision", user.securityPolicyChange);
        return ReturnObject(answer);
    }
    if (ParsedBody_->has("objectType") && ParsedBody_->has("objectId")) {
        if (!ParsedBody_->get("objectType").isString() || !ParsedBody_->get("objectId").isString())
            return BadRequest(RESTAPI::Errors::InvalidJSONDocument);
        const auto kind = ParsedBody_->getValue<std::string>("objectType");
        const auto id = ParsedBody_->getValue<std::string>("objectId");
        if (kind == "inventory") resource = UserAccess::ResolveStoredDevice(id);
        else if (kind == "entity" || kind == "venue") resource = UserAccess::ResolveStoredScope({kind, id});
        else if (kind == "configuration") {
            ProvObjects::DeviceConfiguration object;
            if (StorageService()->ConfigurationDB().GetRecord("id", id, object) && object.subscriber.empty())
                resource = UserAccess::ResolveOwner(object.entity, object.venue);
        } else if (kind == "variable") {
            ProvObjects::VariableBlock object;
            if (StorageService()->VariablesDB().GetRecord("id", id, object) &&
                object.subscriber.empty() && object.inventory.empty())
                resource = UserAccess::ResolveOwner(object.entity, object.venue);
        } else if (kind == "map") {
            ProvObjects::Map object;
            if (StorageService()->MapDB().GetRecord("id", id, object))
                resource = UserAccess::ResolveOwner(object.entity, object.venue);
        } else if (kind == "contact") {
            ProvObjects::Contact object;
            if (StorageService()->ContactDB().GetRecord("id", id, object))
                resource = UserAccess::ResolveStoredScope({"entity", object.entity});
        } else if (kind == "location") {
            ProvObjects::Location object;
            if (StorageService()->LocationDB().GetRecord("id", id, object))
                resource = UserAccess::ResolveStoredScope({"entity", object.entity});
        }
    } else if (ParsedBody_->has("serialNumber")) {
        if (ParsedBody_->has("scopeType") || ParsedBody_->has("scopeId") ||
            !ParsedBody_->get("serialNumber").isString())
            return BadRequest(RESTAPI::Errors::InvalidJSONDocument);
        resource = UserAccess::ResolveStoredDevice(ParsedBody_->getValue<std::string>("serialNumber"));
    } else {
        if (!ParsedBody_->has("scopeType") || !ParsedBody_->has("scopeId") ||
            !ParsedBody_->get("scopeType").isString() || !ParsedBody_->get("scopeId").isString())
            return BadRequest(RESTAPI::Errors::InvalidJSONDocument);
        resource = UserAccess::ResolveStoredScope({ParsedBody_->getValue<std::string>("scopeType"),
                                                   ParsedBody_->getValue<std::string>("scopeId")});
    }
    const bool allowed = UserAccess::AllowsUser(user, resource, capability);
    Poco::JSON::Object answer;
    answer.set("allowed", allowed);
    answer.set("secretsAllowed", UserAccess::AllowsUser(user, resource, "secrets.read"));
    answer.set("policyRevision", user.securityPolicyChange);
    Logger_.information(fmt::format("Access decision: actor={} capability={} allowed={} revision={}",
                                   user.id, capability, allowed, user.securityPolicyChange));
    return ReturnObject(answer);
}
}
