#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace OpenWifi::VenueAlerts {
struct Rule {
    std::string type;
    bool enabled = true;
    int delaySeconds = 300, recoveryDelaySeconds = 60, repeatSeconds = 0;
    bool recovery = true, email = true, sms = false;
};
struct QuietHours {
    bool enabled = false;
    std::string timezone = "Europe/London", start = "22:00", end = "08:00";
    std::vector<int> days{1,2,3,4,5,6,7};
};
struct Policy {
    bool enabled = false;
    std::vector<std::string> emails, phones;
    std::vector<Rule> rules;
    QuietHours quietHours;
    int64_t muteUntil = 0;
    std::string groupBy = "venue";
    int groupWindowSeconds = 60;
};
// Throws std::invalid_argument. JSON callers must also enforce strict JSON types
// and reject unknown fields before constructing these typed values.
void Validate(Policy &policy);
enum class Observation { Unknown, Healthy, Fault };
struct RecipientState {
    bool faultAccepted = false, pendingRecovery = false, held = false;
    int64_t lastAccepted = 0, lastAttempt = -1;
    std::string pendingId;
};
struct AlertState {
    std::string venue, serial, type;
    Observation phase = Observation::Unknown, lastObservation = Observation::Unknown;
    int64_t lastObserved = -1, elapsed = 0;
    std::map<std::string, RecipientState> recipients;
};
struct Snapshot {
    uint64_t sequence = 0;
    std::map<std::string, AlertState> alerts;
};
struct Delivery {
    std::string id, key, venue, serial, type, channel, recipient;
    bool recovery = false;
};
// Single-threaded: integration must serialize Observe/Accept/Reject/persistence.
// Persist reservations before sending; persist Accept afterwards. An ambiguous
// provider response or restart with a reservation is held until phase change.
// This prefers a potentially missed notification over duplicate alert storms;
// it does not claim distributed exactly-once delivery.
class Engine {
public:
    explicit Engine(int64_t maxObservationGap = 120);
    std::vector<Delivery> Observe(const std::string &venue, const std::string &serial,
        const std::string &type, Observation observation, int64_t now,
        const Policy &policy, bool quietNow = false);
    bool Accept(const Delivery &delivery, int64_t now);
    bool Reject(const Delivery &delivery, int64_t now);
    bool Hold(const Delivery &delivery, int64_t now);
    bool IsPending(const Delivery &delivery) const;
    Snapshot Save() const { return state_; }
    void Restore(const Snapshot &snapshot);
    // Call each collection pass with all current managed serial -> venue pairs.
    void RetainDevices(const std::map<std::string,std::string> &devices);
private:
    Snapshot state_;
    int64_t maxGap_;
};
} // namespace OpenWifi::VenueAlerts
