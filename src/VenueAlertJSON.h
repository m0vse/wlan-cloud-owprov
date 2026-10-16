#pragma once
#include "VenueAlertPolicy.h"
#include <Poco/JSON/Array.h>
#include <Poco/JSON/Object.h>
#include <stdexcept>
#include <set>
#include <algorithm>

namespace OpenWifi::VenueAlerts {
using Object = Poco::JSON::Object;
using Array = Poco::JSON::Array;
inline void Fields(const Object &o,std::initializer_list<const char*> names) {
    std::set<std::string> allowed(names.begin(),names.end());
    for(const auto &v:o) if(!allowed.count(v.first))throw std::invalid_argument("unknown field");
}
inline bool Boolean(const Object &o,const char *n) {
    if(!o.has(n)||o.get(n).type()!=typeid(bool))throw std::invalid_argument("boolean required");
    return o.getValue<bool>(n);
}
inline std::string String(const Object &o,const char *n) {
    if(!o.has(n)||!o.get(n).isString())throw std::invalid_argument("string required");
    return o.getValue<std::string>(n);
}
inline int64_t Integer(const Object &o,const char *n) {
    if(!o.has(n)||!o.get(n).isInteger()||o.get(n).type()==typeid(bool))throw std::invalid_argument("integer required");
    return o.getValue<int64_t>(n);
}
inline std::vector<std::string> Strings(const Object &o,const char *n) {
    auto a=o.getArray(n);if(!a||a->size()>20)throw std::invalid_argument("recipient array required");
    std::vector<std::string> out;
    for(const auto &v:*a){if(!v.isString())throw std::invalid_argument("string recipient required");out.push_back(v.convert<std::string>());}return out;
}
inline Policy ParsePolicy(const Object &o) {
    Fields(o,{"enabled","emails","phones","rules","quietHours","muteUntil","groupBy","groupWindowSeconds"});
    Policy p;p.enabled=Boolean(o,"enabled");p.emails=Strings(o,"emails");p.phones=Strings(o,"phones");p.muteUntil=Integer(o,"muteUntil");
    if(o.has("groupBy"))p.groupBy=String(o,"groupBy");
    if(o.has("groupWindowSeconds")){auto n=Integer(o,"groupWindowSeconds");if(n<0||n>3600)throw std::invalid_argument("group window");p.groupWindowSeconds=n;}
    auto rules=o.getArray("rules");if(!rules||rules->size()>3)throw std::invalid_argument("rules required");
    for(size_t i=0;i<rules->size();++i){auto r=rules->getObject(i);if(!r)throw std::invalid_argument("rule object required");
        Fields(*r,{"type","enabled","delaySeconds","recoveryDelaySeconds","repeatSeconds","recovery","email","sms"});Rule v;
        v.type=String(*r,"type");v.enabled=Boolean(*r,"enabled");v.recovery=Boolean(*r,"recovery");v.email=Boolean(*r,"email");v.sms=Boolean(*r,"sms");
        auto delay=Integer(*r,"delaySeconds"),recovery=Integer(*r,"recoveryDelaySeconds"),repeat=Integer(*r,"repeatSeconds");
        if(delay<0||delay>604800||recovery<0||recovery>604800||repeat<0||repeat>604800)throw std::invalid_argument("rule duration");
        v.delaySeconds=delay;v.recoveryDelaySeconds=recovery;v.repeatSeconds=repeat;p.rules.push_back(v);
    }
    auto q=o.getObject("quietHours");if(!q)throw std::invalid_argument("quiet hours required");
    Fields(*q,{"enabled","timezone","start","end","days"});p.quietHours.enabled=Boolean(*q,"enabled");p.quietHours.timezone=String(*q,"timezone");p.quietHours.start=String(*q,"start");p.quietHours.end=String(*q,"end");
    auto days=q->getArray("days");if(!days||days->size()>7)throw std::invalid_argument("quiet days required");p.quietHours.days.clear();
    for(auto &v:*days){if(!v.isInteger()||v.type()==typeid(bool)||v.convert<int64_t>()<1||v.convert<int64_t>()>7)throw std::invalid_argument("quiet day");p.quietHours.days.push_back(v.convert<int>());}
    Validate(p);return p;
}
inline Object PolicyJSON(const Policy &p) {
    Object o;o.set("enabled",p.enabled);Array e,f,rules;for(auto &v:p.emails)e.add(v);for(auto &v:p.phones)f.add(v);o.set("emails",e);o.set("phones",f);
    for(auto &r:p.rules){Object v;v.set("type",r.type);v.set("enabled",r.enabled);v.set("delaySeconds",r.delaySeconds);v.set("recoveryDelaySeconds",r.recoveryDelaySeconds);v.set("repeatSeconds",r.repeatSeconds);v.set("recovery",r.recovery);v.set("email",r.email);v.set("sms",r.sms);rules.add(v);}o.set("rules",rules);
    Object q;auto &v=p.quietHours;q.set("enabled",v.enabled);q.set("timezone",v.timezone);q.set("start",v.start);q.set("end",v.end);Array days;for(auto d:v.days)days.add(d);q.set("days",days);o.set("quietHours",q);o.set("muteUntil",p.muteUntil);o.set("groupBy",p.groupBy);o.set("groupWindowSeconds",p.groupWindowSeconds);return o;
}
inline Object DeliveryJSON(const Delivery &d) {Object o;o.set("id",d.id);o.set("key",d.key);o.set("venue",d.venue);o.set("serial",d.serial);o.set("type",d.type);o.set("channel",d.channel);o.set("recipient",d.recipient);o.set("recovery",d.recovery);return o;}
inline std::string AlertKey(const std::string &venue,const std::string &serial,const std::string &type) {
    return std::to_string(venue.size())+":"+venue+std::to_string(serial.size())+":"+serial+type;
}
inline void AlertIdentity(const std::string &venue,const std::string &serial,const std::string &type) {
    if(venue.empty() || venue.size()>256 || serial.empty() || serial.size()>256 ||
        (type!="down" && type!="critical" && type!="radio"))throw std::invalid_argument("alert identity");
}
inline void AlertRecipient(const std::string &channel,const std::string &recipient) {
    Policy p;
    if(channel=="email")p.emails={recipient};else if(channel=="sms")p.phones={recipient};else throw std::invalid_argument("alert channel");
    Validate(p);
}
inline uint64_t AlertSequence(const std::string &id) {
    if(id.empty() || id.size()>20 || !std::all_of(id.begin(),id.end(),[](char c){return c>='0'&&c<='9';}))throw std::invalid_argument("delivery id");
    size_t consumed=0;auto n=std::stoull(id,&consumed);if(!n || consumed!=id.size())throw std::invalid_argument("delivery id");
    return n;
}
inline Delivery ParseDelivery(const Object &o) {
    Fields(o,{"id","key","venue","serial","type","channel","recipient","recovery"});
    Delivery d;d.id=String(o,"id");d.key=String(o,"key");d.venue=String(o,"venue");d.serial=String(o,"serial");d.type=String(o,"type");d.channel=String(o,"channel");d.recipient=String(o,"recipient");d.recovery=Boolean(o,"recovery");
    AlertIdentity(d.venue,d.serial,d.type);AlertRecipient(d.channel,d.recipient);AlertSequence(d.id);
    if(d.key!=AlertKey(d.venue,d.serial,d.type))throw std::invalid_argument("delivery key");
    return d;
}
inline Object SnapshotJSON(const Snapshot &s) {
    Object o;o.set("sequence",s.sequence);Array alerts;
    for(auto &[key,a]:s.alerts){Object v;v.set("key",key);v.set("venue",a.venue);v.set("serial",a.serial);v.set("type",a.type);v.set("phase",static_cast<int>(a.phase));v.set("lastObservation",static_cast<int>(a.lastObservation));v.set("lastObserved",a.lastObserved);v.set("elapsed",a.elapsed);Object recipients;
        for(auto &[k,r]:a.recipients){Object x;x.set("faultAccepted",r.faultAccepted);x.set("pendingRecovery",r.pendingRecovery);x.set("lastAccepted",r.lastAccepted);x.set("lastAttempt",r.lastAttempt);x.set("pendingId",r.pendingId);x.set("held",r.held);recipients.set(k,x);}v.set("recipients",recipients);alerts.add(v);
    }o.set("alerts",alerts);return o;
}
inline Snapshot ParseSnapshot(const Object &o) {
    Fields(o,{"sequence","alerts"});
    Snapshot s;auto sequence=Integer(o,"sequence");if(sequence<0)throw std::invalid_argument("sequence");s.sequence=sequence;auto list=o.getArray("alerts");if(!list||list->size()>30000)throw std::invalid_argument("alert state capacity");
    for(size_t i=0;i<list->size();++i){auto v=list->getObject(i);if(!v)throw std::invalid_argument("alert state");AlertState a;a.venue=String(*v,"venue");a.serial=String(*v,"serial");a.type=String(*v,"type");
        Fields(*v,{"key","venue","serial","type","phase","lastObservation","lastObserved","elapsed","recipients"});AlertIdentity(a.venue,a.serial,a.type);
        auto phase=Integer(*v,"phase"),last=Integer(*v,"lastObservation");if(phase<0||phase>2||last<0||last>2)throw std::invalid_argument("phase");a.phase=static_cast<Observation>(phase);a.lastObservation=static_cast<Observation>(last);a.lastObserved=Integer(*v,"lastObserved");a.elapsed=Integer(*v,"elapsed");
        if(a.lastObserved < -1 || a.elapsed<0 || a.elapsed>315360000)throw std::invalid_argument("observation timing");
        auto recipients=v->getObject("recipients");if(!recipients||recipients->size()>40)throw std::invalid_argument("recipient state");
        for(auto &kv:*recipients){auto x=recipients->getObject(kv.first);if(!x)throw std::invalid_argument("recipient state");
            Fields(*x,{"faultAccepted","pendingRecovery","lastAccepted","lastAttempt","pendingId","held"});
            auto colon=kv.first.find(':');if(colon==std::string::npos)throw std::invalid_argument("recipient key");AlertRecipient(kv.first.substr(0,colon),kv.first.substr(colon+1));
            RecipientState r;r.faultAccepted=Boolean(*x,"faultAccepted");r.pendingRecovery=Boolean(*x,"pendingRecovery");r.lastAccepted=Integer(*x,"lastAccepted");r.lastAttempt=Integer(*x,"lastAttempt");r.pendingId=String(*x,"pendingId");r.held=x->has("held")?Boolean(*x,"held"):false;
            if(r.lastAccepted<0 || r.lastAttempt < -1 || (!r.pendingId.empty() && AlertSequence(r.pendingId)>s.sequence))throw std::invalid_argument("recipient timing/id");
            a.recipients[kv.first]=r;
        }
        auto key=String(*v,"key");if(key!=AlertKey(a.venue,a.serial,a.type) || s.alerts.count(key))throw std::invalid_argument("duplicate or invalid alert key");s.alerts[key]=a;
    }return s;
}
} // namespace OpenWifi::VenueAlerts
