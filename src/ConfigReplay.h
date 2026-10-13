#pragma once
#include <nlohmann/json.hpp>
#include <cstdint>
#include <string>

namespace OpenWifi::ConfigReplay {
struct Decision { bool unchanged=false; std::uint64_t version=0; };
// Only an online AP's own applied UUID proves that stored content is active.
// Stored/queued configuration by itself is not evidence of a successful apply.
inline Decision Evaluate(const std::string& serial,const std::string& desired,
                         const std::string& snapshot) {
    try {
        using Json=nlohmann::json;
        auto proposed=Json::parse(desired),state=Json::parse(snapshot);
        const auto& device=state.at("deviceInfo");
        const auto& connection=state.at("connectionInfo");
        if (!proposed.is_object() || proposed.empty() ||
            device.value("serialNumber",std::string{})!=serial ||
            !connection.at("connected").is_boolean() || !connection.at("connected").get<bool>() ||
            !device.at("pendingConfiguration").is_string() || !device.at("pendingConfiguration").get<std::string>().empty() ||
            !device.at("pendingUUID").is_number_integer() || device.at("pendingUUID")!=0)
            return {};
        auto current=device.at("configuration");
        if (current.is_string()) current=Json::parse(current.get<std::string>());
        if (!current.is_object() || current.empty() || !current.contains("uuid") ||
            !current.at("uuid").is_number_integer() || current.at("uuid")<=0 ||
            !connection.at("UUID").is_number_integer() || connection.at("UUID")!=current.at("uuid") ||
            !device.at("UUID").is_number_integer() || device.at("UUID")!=current.at("uuid"))
            return {};
        auto version=current.at("uuid").get<std::uint64_t>();
        current.erase("uuid"); proposed.erase("uuid");
        if (current.empty() || proposed.empty()) return {};
        return {current==proposed,version};
    } catch (...) { return {}; }
}
}
