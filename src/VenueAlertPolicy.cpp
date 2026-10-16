#include "VenueAlertPolicy.h"
#include <algorithm>
#include <cctype>
#include <regex>
#include <set>
#include <stdexcept>

namespace OpenWifi::VenueAlerts {
namespace {
void Require(bool ok, const char *why) { if (!ok) throw std::invalid_argument(why); }
bool Type(const std::string &s) { return s=="down" || s=="critical" || s=="radio"; }
std::string Key(const std::string &venue,const std::string &serial,const std::string &type) {
    return std::to_string(venue.size())+":"+venue+std::to_string(serial.size())+":"+serial+type;
}
std::string RecipientKey(const std::string &channel,const std::string &recipient) {
    return channel+":"+recipient;
}
void Unique(std::vector<std::string> &values) {
    std::set<std::string> seen;
    values.erase(std::remove_if(values.begin(),values.end(),[&](const auto &v){return !seen.insert(v).second;}),values.end());
}
}
void Validate(Policy &p) {
    Require(p.emails.size()<=20 && p.phones.size()<=20,"at most 20 recipients per channel");
    const std::regex email(R"(^[^\s@<>:,;]+@[^\s@<>:,;]+\.[^\s@<>:,;]+$)");
    const std::regex phone(R"(^\+[1-9][0-9]{6,14}$)");
    for (auto &v:p.emails) {
        Require(v.size()<=254 && std::all_of(v.begin(),v.end(),[](unsigned char c){return c>=33 && c<=126;}) && std::regex_match(v,email),"invalid email recipient");
        // Domain is case insensitive; preserve local part semantics.
        auto at=v.find('@');
        std::transform(v.begin()+at+1,v.end(),v.begin()+at+1,[](unsigned char c){return std::tolower(c);});
    }
    for (const auto &v:p.phones) Require(std::regex_match(v,phone),"phone must be E.164");
    Unique(p.emails); Unique(p.phones);
    Require(p.rules.size()<=3,"at most three fault rules");
    std::set<std::string> types;
    for (const auto &r:p.rules) {
        Require(Type(r.type) && types.insert(r.type).second,"unknown or duplicate rule type");
        Require(r.delaySeconds>=0 && r.delaySeconds<=604800 && r.recoveryDelaySeconds>=0 && r.recoveryDelaySeconds<=604800,"delay outside bounds");
        Require(r.repeatSeconds==0 || (r.repeatSeconds>=60 && r.repeatSeconds<=604800),"repeat must be zero or 60..604800");
    }
    Require(p.muteUntil>=0,"muteUntil must not be negative");
    Require(p.groupBy=="venue" || p.groupBy=="entity","groupBy must be venue or entity");
    Require(p.groupWindowSeconds>=0 && p.groupWindowSeconds<=3600,"group window must be 0..3600");
    const std::regex clock(R"(^([01][0-9]|2[0-3]):[0-5][0-9]$)");
    Require(std::regex_match(p.quietHours.start,clock) && std::regex_match(p.quietHours.end,clock),"invalid quiet hours time");
    const auto &z=p.quietHours.timezone;
    Require(!z.empty() && z.size()<=128 && z.front()!='/' && z.find("..") == std::string::npos &&
        std::all_of(z.begin(),z.end(),[](unsigned char c){return std::isalnum(c)||c=='/'||c=='_'||c=='-'||c=='+';}),"invalid timezone name");
    std::set<int> days;
    Require(!p.quietHours.days.empty() && p.quietHours.days.size()<=7,"invalid quiet days");
    for(int d:p.quietHours.days) Require(d>=1 && d<=7 && days.insert(d).second,"invalid or duplicate quiet day");
    // Integration validates timezone exists in IANA tzdata and evaluates quietNow.
}
Engine::Engine(int64_t gap):maxGap_(gap) { Require(gap>0,"observation gap must be positive"); }
std::vector<Delivery> Engine::Observe(const std::string &venue,const std::string &serial,
    const std::string &type,Observation observation,int64_t now,const Policy &policy,bool quietNow) {
    Require(Type(type) && !venue.empty() && !serial.empty() && now>=0,"invalid observation identity/time");
    const auto key=Key(venue,serial,type);
    auto rule=std::find_if(policy.rules.begin(),policy.rules.end(),[&](const auto &r){return r.type==type;});
    if(!policy.enabled || rule==policy.rules.end() || !rule->enabled) {state_.alerts.erase(key);return {};}
    auto &a=state_.alerts[key]; a.venue=venue;a.serial=serial;a.type=type;
    std::map<std::string,std::pair<std::string,std::string>> recipients;
    if(rule->email) for(const auto &r:policy.emails) recipients[RecipientKey("email",r)]={"email",r};
    if(rule->sms) for(const auto &r:policy.phones) recipients[RecipientKey("sms",r)]={"sms",r};
    for(auto it=a.recipients.begin();it!=a.recipients.end();) {
        if(!recipients.count(it->first)) it=a.recipients.erase(it); else ++it;
    }
    if(a.lastObserved>now) {
        a.elapsed=0; a.lastObservation=Observation::Unknown;
        for(auto &[k,r]:a.recipients) {r.lastAttempt=now;r.lastAccepted=now;r.pendingId.clear();}
    }
    for(auto &[k,r]:a.recipients) {
        if(r.lastAttempt>now) r.lastAttempt=now;
        if(r.lastAccepted>now) r.lastAccepted=now;
    }
    if(observation==Observation::Unknown) {a.lastObservation=observation;a.lastObserved=now;return {};}
    if(observation!=a.phase) {
        a.phase=observation;a.elapsed=0;
        // In-flight jobs from the previous phase must never be accepted later.
        for(auto &[k,r]:a.recipients) {r.pendingId.clear();r.held=false;}
    } else if(a.lastObservation==observation && a.lastObserved>=0 && now>=a.lastObserved && now-a.lastObserved<=maxGap_) {
        a.elapsed=std::min<int64_t>(604800,a.elapsed+now-a.lastObserved);
    }
    a.lastObservation=observation;a.lastObserved=now;
    std::vector<Delivery> deliveries;
    if(quietNow || now<policy.muteUntil) return deliveries;
    const bool recovery=observation==Observation::Healthy;
    if(a.elapsed<(recovery?rule->recoveryDelaySeconds:rule->delaySeconds)) return deliveries;
    for(const auto &[rk,target]:recipients) {
        auto &r=a.recipients[rk];
        if(r.held || !r.pendingId.empty()) continue;
        if(recovery && !r.faultAccepted) continue;
        if(recovery && !rule->recovery) {r=RecipientState{};continue;}
        if(!recovery && r.faultAccepted && (rule->repeatSeconds==0 || now-r.lastAccepted<rule->repeatSeconds)) continue;
        if(r.lastAttempt>=0 && now-r.lastAttempt<60) continue;
        // Only explicitly rejected/not-attempted jobs are automatically retried.
        r.pendingId=std::to_string(++state_.sequence);r.pendingRecovery=recovery;r.lastAttempt=now;
        deliveries.push_back({r.pendingId,key,venue,serial,type,target.first,target.second,recovery});
    }
    return deliveries;
}
bool Engine::Accept(const Delivery &d,int64_t now) {
    auto a=state_.alerts.find(d.key); if(a==state_.alerts.end()) return false;
    auto r=a->second.recipients.find(RecipientKey(d.channel,d.recipient));
    if(r==a->second.recipients.end() || r->second.pendingId!=d.id || d.id.empty() ||
       r->second.pendingRecovery!=d.recovery || now<r->second.lastAttempt) return false;
    auto &s=r->second; s.pendingId.clear();s.lastAccepted=now;s.faultAccepted=!d.recovery;
    return true;
}
bool Engine::IsPending(const Delivery &d) const {
    const auto a=state_.alerts.find(d.key);if(a==state_.alerts.end()) return false;
    const auto r=a->second.recipients.find(RecipientKey(d.channel,d.recipient));
    return r!=a->second.recipients.end() && !d.id.empty() && r->second.pendingId==d.id &&
        !r->second.held && r->second.pendingRecovery==d.recovery &&
        a->second.venue==d.venue && a->second.serial==d.serial && a->second.type==d.type &&
        a->second.lastObservation!=Observation::Unknown &&
        a->second.phase==(d.recovery?Observation::Healthy:Observation::Fault);
}
bool Engine::Reject(const Delivery &d,int64_t now) {
    auto a=state_.alerts.find(d.key);if(a==state_.alerts.end()) return false;
    auto r=a->second.recipients.find(RecipientKey(d.channel,d.recipient));
    if(r==a->second.recipients.end() || r->second.pendingId!=d.id || d.id.empty()) return false;
    r->second.pendingId.clear();r->second.lastAttempt=std::max(now,r->second.lastAttempt);return true;
}
bool Engine::Hold(const Delivery &d,int64_t now) {
    auto a=state_.alerts.find(d.key);if(a==state_.alerts.end()) return false;
    auto r=a->second.recipients.find(RecipientKey(d.channel,d.recipient));
    if(r==a->second.recipients.end() || r->second.pendingId!=d.id || d.id.empty()) return false;
    r->second.pendingId.clear();r->second.held=true;
    r->second.lastAttempt=std::max(now,r->second.lastAttempt);return true;
}
void Engine::Restore(const Snapshot &snapshot) {
    // Restoring must never count daemon downtime as observed continuity.
    state_=snapshot;
    for(auto &[key,a]:state_.alerts) {
        a.lastObservation=Observation::Unknown;a.lastObserved=-1;
        for(auto &[k,r]:a.recipients) {
            if(!r.pendingId.empty()) {r.held=true;r.pendingId.clear();}
        }
    }
}
void Engine::RetainDevices(const std::map<std::string,std::string> &devices) {
    for(auto it=state_.alerts.begin();it!=state_.alerts.end();) {
        auto d=devices.find(it->second.serial);
        if(d==devices.end() || d->second!=it->second.venue) it=state_.alerts.erase(it); else ++it;
    }
}
} // namespace OpenWifi::VenueAlerts
