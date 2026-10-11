#pragma once
#include "UserAccess.h"
#include "framework/RESTAPI_Handler.h"

namespace OpenWifi {
inline void ScopedEntityTree(RESTAPIHandler &handler) {
    std::map<std::string, Poco::JSON::Object::Ptr> entities, venues;
    std::map<std::string, std::string> entityParents, venueParents, venueEntities;
    const auto &user = handler.AccessSubject();
    for (uint64_t start = 0;; start += 500) {
        EntityDB::RecordVec page;
        if (!StorageService()->EntityDB().GetRecords(start, 500, page, "", " ORDER BY id ASC "))
            return handler.UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
        for (const auto &record : page) {
            if (!UserAccess::AllowsUser(user, UserAccess::ResolveStoredScope({"entity", record.info.id}), "devices.read")) continue;
            auto node = Poco::makeShared<Poco::JSON::Object>();
            node->set("uuid", record.info.id); node->set("name", record.info.name); node->set("type", "entity");
            node->set("children", Poco::makeShared<Poco::JSON::Array>());
            node->set("venues", Poco::makeShared<Poco::JSON::Array>());
            entities[record.info.id] = node; entityParents[record.info.id] = record.parent;
        }
        if (page.size() < 500) break;
    }
    for (uint64_t start = 0;; start += 500) {
        VenueDB::RecordVec page;
        if (!StorageService()->VenueDB().GetRecords(start, 500, page, "", " ORDER BY id ASC "))
            return handler.UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);
        for (const auto &record : page) {
            if (!UserAccess::AllowsUser(user, UserAccess::ResolveStoredScope({"venue", record.info.id}), "devices.read")) continue;
            auto node = Poco::makeShared<Poco::JSON::Object>();
            node->set("uuid", record.info.id); node->set("name", record.info.name); node->set("type", "venue");
            node->set("children", Poco::makeShared<Poco::JSON::Array>());
            venues[record.info.id] = node; venueParents[record.info.id] = record.parent;
            venueEntities[record.info.id] = record.entity;
        }
        if (page.size() < 500) break;
    }
    auto root = Poco::makeShared<Poco::JSON::Object>();
    root->set("uuid", UserAccess::PlatformRoot.id); root->set("name", "Sites"); root->set("type", "entity");
    root->set("children", Poco::makeShared<Poco::JSON::Array>());
    root->set("venues", Poco::makeShared<Poco::JSON::Array>());
    for (const auto &[id, node] : entities) {
        auto found = entities.find(entityParents[id]);
        (found == entities.end() ? root : found->second)->getArray("children")->add(node);
    }
    for (const auto &[id, node] : venues) {
        auto parent = venues.find(venueParents[id]);
        if (parent != venues.end()) parent->second->getArray("children")->add(node);
        else {
            auto entity = entities.find(venueEntities[id]);
            (entity == entities.end() ? root : entity->second)->getArray("venues")->add(node);
        }
    }
    // The tree was built exclusively from authorized records above; ordinary
    // object-response relation suppression must not erase its checked forest.
    std::ostringstream output; root->stringify(output);
    handler.ReturnRawJSON(output.str());
}

template <class Record> UserAccess::Resource RecordScope(const std::string &kind, const Record &record) {
    if constexpr (std::is_same_v<Record, ProvObjects::DeviceConfiguration>)
        if (!record.subscriber.empty()) return {};
    if constexpr (std::is_same_v<Record, ProvObjects::VariableBlock>)
        if (!record.subscriber.empty() || !record.inventory.empty()) return {};
    if constexpr (std::is_same_v<Record, ProvObjects::Entity> || std::is_same_v<Record, ProvObjects::Venue>)
        return UserAccess::ResolveStoredScope({kind, record.info.id});
    else if constexpr (std::is_same_v<Record, ProvObjects::InventoryTag>)
        return UserAccess::ResolveStoredDevice(record.serialNumber);
    else if constexpr (std::is_same_v<Record, ProvObjects::Contact> || std::is_same_v<Record, ProvObjects::Location>)
        return UserAccess::ResolveStoredScope({"entity", record.entity});
    else return UserAccess::ResolveOwner(record.entity, record.venue);
}

template <class DB> bool ScopedReadList(DB &database, RESTAPIHandler &handler,
                                      const std::string &kind, const std::string &field) {
    if (!handler.RestrictedAccess()) return false;
    if (kind == "inventory" && handler.GetBoolParameter("orderSpec")) return false;
    if (kind == "entity" && handler.GetBoolParameter("getTree")) { ScopedEntityTree(handler); return true; }
    typename DB::RecordVec page;
    Poco::JSON::Array answer;
    const auto &user = handler.AccessSubject();
    const auto capability = kind == "configuration" ? "configuration.read" : "devices.read";
    uint64_t visible = 0;
    const auto offset = handler.GetParameter("offset", uint64_t{0});
    const auto limit = handler.GetParameter("limit", uint64_t{100});
    const auto selected = handler.SelectedRecords();
    for (uint64_t start = 0;; start += 500) {
        page.clear();
        if (!database.GetRecords(start, 500, page, "", " ORDER BY id ASC ")) {
            handler.UnAuthorized(RESTAPI::Errors::ACCESS_DENIED); return true;
        }
        for (const auto &record : page) {
            if (!selected.empty() && std::find(selected.begin(), selected.end(), record.info.id) == selected.end()) continue;
            Poco::JSON::Object recordObject; record.to_json(recordObject);
            bool matches = true;
            for (const auto &key : {"entity", "venue", "serialNumber"}) {
                auto requested = handler.GetParameter(key, "");
                if (!requested.empty() && recordObject.optValue<std::string>(key, "") != requested) matches = false;
            }
            if (!matches) continue;
            auto resource = RecordScope(kind, record);
            if (!UserAccess::AllowsUser(user, resource, capability)) continue;
            if (visible++ < offset || (limit && answer.size() >= limit)) continue;
            Poco::JSON::Object object;
            record.to_json(object);
            // Relations need their own scope checks; do not expand or expose
            // unvalidated IDs merely because the containing record is visible.
            for (const auto &key : {"inUse", "children", "venues", "devices", "contacts", "locations",
                    "managementRoles", "managementPolicies", "maps", "variables", "access"})
                if (object.has(key)) object.set(key, Poco::JSON::Array{});
            for (const auto &key : {"managementPolicy", "managementRole"})
                if (object.has(key)) object.set(key, "");
            UserAccess::FilterConfigurationReferences(user, object);
            if (!UserAccess::AllowsUser(user, resource, "secrets.read")) UserAccess::RedactSecrets(object);
            if (kind == "inventory" && handler.GetBoolParameter("serialOnly"))
                answer.add(object.optValue<std::string>("serialNumber", ""));
            else answer.add(object);
        }
        if (page.size() < 500) break;
    }
    if (handler.GetBoolParameter("countOnly")) handler.ReturnCountOnly(visible);
    else {
        Poco::JSON::Object object;
        object.set(kind == "inventory" && handler.GetBoolParameter("serialOnly") ? "serialNumbers" : field, answer);
        handler.ReturnObject(object);
    }
    return true;
}
}
