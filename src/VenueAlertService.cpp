#include "VenueAlertService.h"
#include "VenueAlertQuietHours.h"
#include "StorageService.h"
#include "UserAccess.h"
#include "framework/OpenAPIRequests.h"
#include "framework/MicroServiceNames.h"
#include "framework/MicroServiceFuncs.h"
#include <Poco/JSON/Parser.h>
#include <Poco/URI.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sstream>
#include <cmath>
#include <cctype>

namespace OpenWifi {
namespace {
using namespace VenueAlerts;
int64_t AlertNow(){return std::time(nullptr);}
std::string ScopeKey(const std::string &kind,const std::string &id){return kind+"/"+id;}
std::pair<std::string,std::string> Owner(const std::string &value){return value.rfind("entity/",0)==0?std::make_pair(std::string("entity"),value.substr(7)):std::make_pair(std::string("venue"),value);}
std::string OwnerKey(const ProvObjects::InventoryTag &d){return d.venue.empty()?ScopeKey("entity",d.entity):d.venue;}
std::vector<UserAccess::Scope> Lineage(const std::string &kind,const std::string &id){
    auto r=UserAccess::ResolveStoredScope({kind,id});if(!r.ownershipResolved)return {};
    std::vector<UserAccess::Scope> chain{r.scope};chain.insert(chain.end(),r.ancestors.begin(),r.ancestors.end());
    if(!(chain.back()==UserAccess::PlatformRoot))chain.push_back(UserAccess::PlatformRoot);return chain;
}
std::string ScopeName(const std::string &kind,const std::string &id){
    if(kind=="venue"){ProvObjects::Venue v;if(StorageService()->VenueDB().GetRecord("id",id,v))return v.info.name;}
    else {ProvObjects::Entity e;if(StorageService()->EntityDB().GetRecord("id",id,e))return e.info.name;}
    return id;
}
Object::Ptr GetObject(const Object &o,const std::string &name){
    if(!o.has(name))return {};auto v=o.get(name);if(v.isString()){Poco::JSON::Parser p;return p.parse(v.convert<std::string>()).extract<Object::Ptr>();}return o.getObject(name);
}
bool True(const Object &o,const char *key){return o.has(key)&&o.get(key).type()==typeid(bool)&&o.getValue<bool>(key);}
bool PowerOnly(const Object &payload,const Object &fault){
    if(fault.optValue<std::string>("code","")!="radio_operating_mismatch")return false;
    auto reports=payload.getObject("radio_operating");if(!reports)return false;
    auto report=reports->getObject(fault.optValue<std::string>("resource",""));if(!report)return false;
    auto ch=report->getObject("channel"),width=report->getObject("width"),power=report->getObject("power");
    return report->optValue<std::string>("status","")=="failed"&&report->optValue<std::string>("reason","").empty()&&
      report->optValue<std::string>("radio","")==fault.optValue<std::string>("radio","missing")&&ch&&width&&power&&
      ch->optValue<std::string>("status","")=="confirmed"&&width->optValue<std::string>("status","")=="confirmed"&&power->optValue<std::string>("status","")=="mismatch"&&
      power->has("requested_dbm")&&power->has("reported_dbm")&&power->get("requested_dbm").isNumeric()&&power->get("reported_dbm").isNumeric()&&std::isfinite(power->getValue<double>("requested_dbm"))&&std::isfinite(power->getValue<double>("reported_dbm"));
}
std::pair<Observation,Observation> Health(const Object::Ptr &response,int64_t now){
    if(!response)return {Observation::Unknown,Observation::Unknown};
    auto values=response->getArray("values");if(!values||values->size()!=1)return {Observation::Unknown,Observation::Unknown};
    auto record=values->getObject(0);if(!record||!record->has("recorded")||!record->get("recorded").isInteger())return {Observation::Unknown,Observation::Unknown};
    auto time=record->getValue<int64_t>("recorded");if(time>now+60||time<now-600)return {Observation::Unknown,Observation::Unknown};
    auto payload=GetObject(*record,"values");if(!payload)return {Observation::Unknown,Observation::Unknown};
    auto faults=payload->getObject("faults");if(!faults||True(*faults,"stale")||(faults->has("stale")&&faults->get("stale").type()!=typeid(bool)))return {Observation::Unknown,Observation::Unknown};
    auto active=faults->getArray("active");if(!active)return {Observation::Unknown,Observation::Unknown};
    bool critical=false,radio=false;
    for(size_t i=0;i<active->size();++i){auto fault=active->getObject(i);if(!fault)return {Observation::Unknown,Observation::Unknown};
        auto severity=fault->optValue<std::string>("severity","");auto code=fault->optValue<std::string>("code","");
        std::transform(severity.begin(),severity.end(),severity.begin(),[](unsigned char c){return std::tolower(c);});
        if(severity!="critical"&&severity!="warning"&&severity!="info")return {Observation::Unknown,Observation::Unknown};
        if(severity=="critical"&&!PowerOnly(*payload,*fault)){critical=true;if(code.find("radio")==0||code.find("wifi")==0)radio=true;}
    }
    return {critical?Observation::Fault:Observation::Healthy,radio?Observation::Fault:Observation::Healthy};
}
std::string Escape(const std::string &s){std::string o;for(char c:s)switch(c){case '&':o+="&amp;";break;case '<':o+="&lt;";break;case '>':o+="&gt;";break;case '"':o+="&quot;";break;case '\'':o+="&#39;";break;default:o+=c;}return o;}
std::string Label(const std::string &type){return type=="down"?"AP offline":type=="radio"?"Radio fault":"Critical fault";}
std::string Date(int64_t when){auto t=static_cast<time_t>(when);std::tm tm{};gmtime_r(&t,&tm);char b[40];std::strftime(b,sizeof(b),"%d %b %Y %H:%M UTC",&tm);return b;}
}
int VenueAlertService::Start(){
    path_=MicroServiceDataDirectory()+"/venue-alerts.json";Load();running_=true;thread_.start(*this);return 0;
}
void VenueAlertService::Stop(){running_=false;thread_.wakeUp();thread_.join();}
void VenueAlertService::run(){while(running_){try{Tick();}catch(...){std::lock_guard lock(mutex_);engine_.SuspendObservations(AlertNow());poco_warning(Logger(),"Alert collection unavailable; no AP states inferred.");}Poco::Thread::trySleep(30000);}}
std::pair<std::string,VenueAlerts::Policy> VenueAlertService::Effective(const std::string &kind,const std::string &id){
    for(auto &scope:Lineage(kind,id)){auto key=ScopeKey(scope.type,scope.id);auto found=policies_.find(key);if(found!=policies_.end())return *found;}
    VenueAlerts::Policy p;for(auto type:{"down","critical","radio"}){VenueAlerts::Rule r;r.type=type;p.rules.push_back(r);}return {"",p};
}
void VenueAlertService::RefreshContext(const std::string &owner){
    auto scope=Owner(owner);auto lineage=Lineage(scope.first,scope.second);auto effective=Effective(scope.first,scope.second);
    VenueAlerts::Object context;context.set("policy",VenueAlerts::PolicyJSON(effective.second));VenueAlerts::Array chain;
    for(auto &s:lineage)chain.add(ScopeKey(s.type,s.id));context.set("lineage",chain);std::ostringstream out;context.stringify(out);
    auto next=out.str();auto prior=contexts_.find(owner);
    if(prior==contexts_.end()||prior->second!=next){std::vector<std::string> keys;for(auto &[key,a]:engine_.Save().alerts)if(a.venue==owner)keys.push_back(key);engine_.ForgetKeys(keys);contexts_[owner]=next;}
}
Poco::JSON::Object VenueAlertService::Get(const std::string &kind,const std::string &id,const SecurityObjects::UserInfo &user){
    std::lock_guard lock(mutex_);auto effective=Effective(kind,id);VenueAlerts::Object o;o.set("available",available_);o.set("settings",VenueAlerts::PolicyJSON(effective.second));
    auto own=ScopeKey(kind,id);o.set("configured",policies_.count(own)>0);o.set("inherited",!effective.first.empty()&&effective.first!=own);
    if(!effective.first.empty()){auto slash=effective.first.find('/');VenueAlerts::Object source;source.set("kind",effective.first.substr(0,slash));
        auto resource=UserAccess::ResolveStoredScope({effective.first.substr(0,slash),effective.first.substr(slash+1)});
        bool visible=UserAccess::AllowsUser(user,resource,"devices.read");source.set("name",visible?ScopeName(effective.first.substr(0,slash),effective.first.substr(slash+1)):"Entity defaults");if(visible)source.set("id",effective.first.substr(slash+1));o.set("sourceScope",source);}
    VenueAlerts::Array history;std::set<std::string> seen;
    for(auto it=events_.rbegin();it!=events_.rend()&&history.size()<100;++it){auto scopes=it->getArray("scopes");bool belongs=false;if(scopes)for(auto &s:*scopes)belongs|=s.toString()==own;
        auto serial=it->optValue<std::string>("device","");auto eventId=it->optValue<std::string>("id","");auto resource=UserAccess::ResolveStoredDevice(serial);
        auto type=it->optValue<std::string>("type","");bool permitted=UserAccess::AllowsUser(user,resource,"devices.read")&&(type=="down"||UserAccess::AllowsUser(user,resource,"diagnostics.read"));
        if(belongs&&seen.insert(eventId).second&&permitted){auto event=*it;event.remove("scopes");history.add(event);}}
    o.set("events",history);return o;
}
VenueAlertService::Result VenueAlertService::Save(const std::string &kind,const std::string &id,const Poco::JSON::Object &body){
    std::lock_guard lock(mutex_);if(!available_)return Result::unavailable;
    try{auto key=ScopeKey(kind,id);auto old=policies_;auto state=engine_.Save();auto queued=queue_;
        auto signature=[&](const std::string &owner){auto scope=Owner(owner);auto p=Effective(scope.first,scope.second);std::ostringstream s;VenueAlerts::PolicyJSON(p.second).stringify(s);return s.str();};
        std::map<std::string,std::string> before;
        for(auto &[k,a]:state.alerts)before[a.venue]=signature(a.venue);
        if(body.size()==1&&body.has("inherit")&&VenueAlerts::Boolean(body,"inherit"))policies_.erase(key);
        else {auto policy=VenueAlerts::ParsePolicy(body);VenueAlerts::ZoneOffset(policy.quietHours.timezone,AlertNow());policies_[key]=policy;}
        // Only changed effective rules are reset; unrelated sites retain their
        // observation timers, accepted deliveries and queued groups.
        std::vector<std::string> changed;
        for(auto &[k,a]:state.alerts)if(before[a.venue]!=signature(a.venue))changed.push_back(k);
        engine_.ForgetKeys(changed);
        queue_.erase(std::remove_if(queue_.begin(),queue_.end(),[&](auto &q){return !engine_.HasReservation(q.delivery);}),queue_.end());
        if(!Persist()){policies_=old;engine_.Restore(state);queue_=queued;return Result::unavailable;}return Result::saved;
    }catch(...){return Result::invalid;}
}
bool VenueAlertService::Persist(){
    using namespace VenueAlerts;
    try{Object doc;doc.set("version",1);Object policies;for(auto &[k,p]:policies_)policies.set(k,PolicyJSON(p));doc.set("policies",policies);doc.set("engine",SnapshotJSON(engine_.Save()));Object contexts;for(auto &[k,v]:contexts_)contexts.set(k,v);doc.set("contexts",contexts);Array queue,events;
        for(auto &q:queue_){Object o;o.set("delivery",DeliveryJSON(q.delivery));o.set("due",q.due);o.set("dispatching",q.dispatching);o.set("group",q.group);o.set("deviceName",q.deviceName);o.set("venueName",q.venueName);o.set("entityName",q.entityName);Array scopes;for(auto &s:q.scopes)scopes.add(s);o.set("scopes",scopes);queue.add(o);}for(auto &e:events_)events.add(e);doc.set("queue",queue);doc.set("events",events);
        std::ostringstream stream;doc.stringify(stream);auto data=stream.str();if(data.size()>16*1024*1024)throw std::runtime_error("state capacity");
        auto name=path_+".XXXXXX";std::vector<char> temp(name.begin(),name.end());temp.push_back(0);int fd=mkstemp(temp.data());if(fd<0)throw std::runtime_error("state create");
        bool ok=fchmod(fd,0600)==0;size_t done=0;while(ok&&done<data.size()){auto n=write(fd,data.data()+done,data.size()-done);if(n<=0)ok=false;else done+=n;}if(ok)ok=fsync(fd)==0;if(close(fd))ok=false;
        if(ok)ok=rename(temp.data(),path_.c_str())==0;if(!ok){unlink(temp.data());throw std::runtime_error("state write");}
        auto dir=path_.substr(0,path_.find_last_of('/'));int dfd=open(dir.c_str(),O_RDONLY|O_DIRECTORY);if(dfd<0)throw std::runtime_error("directory");ok=fsync(dfd)==0;close(dfd);if(!ok)throw std::runtime_error("directory sync");return true;
    }catch(...){available_=false;poco_warning(Logger(),"Alert state unavailable; delivery paused.");return false;}
}
void VenueAlertService::Load(){
    using namespace VenueAlerts;std::lock_guard lock(mutex_);available_=true;
    int fd=open(path_.c_str(),O_RDONLY|O_NOFOLLOW);if(fd<0){if(errno!=ENOENT)available_=false;return;}
    struct stat st{};if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&077)||st.st_size>16*1024*1024){close(fd);available_=false;return;}
    std::string data;char b[8192];ssize_t n;while((n=read(fd,b,sizeof(b)))>0)data.append(b,n);close(fd);
    try{if(n<0)throw std::runtime_error("read");Poco::JSON::Parser parser;auto doc=parser.parse(data).extract<Object::Ptr>();if(Integer(*doc,"version")!=1)throw std::runtime_error("version");
        auto policies=doc->getObject("policies");if(!policies||policies->size()>10000)throw std::runtime_error("policies");for(auto &kv:*policies){auto p=policies->getObject(kv.first);if(!p)throw std::runtime_error("policy");policies_[kv.first]=ParsePolicy(*p);}
        auto saved=doc->getObject("engine");if(!saved)throw std::runtime_error("engine");auto state=ParseSnapshot(*saved);
        // Queued but not dispatched may safely be retried; in-flight sends are
        // conservatively held after restart to avoid duplicate SMS/email storms.
        auto queue=doc->getArray("queue");if(!queue)throw std::runtime_error("queue");std::set<std::string> interrupted;
        for(size_t i=0;i<queue->size();++i){auto q=queue->getObject(i);if(!q)throw std::runtime_error("queue entry");auto delivery=q->getObject("delivery");if(!delivery)throw std::runtime_error("delivery");auto d=ParseDelivery(*delivery);auto a=state.alerts.find(d.key);
            if(a!=state.alerts.end()){auto r=a->second.recipients.find(d.channel+":"+d.recipient);if(r!=a->second.recipients.end()&&r->second.pendingId==d.id){if(Boolean(*q,"dispatching"))interrupted.insert(d.id);else r->second.pendingId.clear();}}
        }engine_.Restore(state);
        auto contexts=doc->getObject("contexts");if(contexts){if(contexts->size()>10000)throw std::runtime_error("contexts");for(auto &kv:*contexts){if(!kv.second.isString())throw std::runtime_error("context");contexts_[kv.first]=kv.second.convert<std::string>();}}
        auto events=doc->getArray("events");if(!events||events->size()>1000)throw std::runtime_error("events");for(size_t i=0;i<events->size();++i){auto e=events->getObject(i);if(e)events_.push_back(*e);}
        for(auto it=events_.rbegin();it!=events_.rend();++it){auto id=it->optValue<std::string>("id","");if(interrupted.erase(id)&&it->optValue<std::string>("status","")=="dispatching")it->set("status","unknown");}
    }catch(...){available_=false;policies_.clear();poco_warning(Logger(),"Saved alert state invalid; delivery paused.");}
}
void VenueAlertService::Event(const Queued &q,const std::string &status,int64_t now,const std::string &provider){
    using namespace VenueAlerts;Object o;o.set("id",q.delivery.id);o.set("type",q.delivery.type);o.set("device",q.delivery.serial);o.set("name",q.deviceName);o.set("venue",q.delivery.venue);o.set("status",status);o.set("channel",q.delivery.channel);o.set("recipient",q.delivery.recipient);o.set("time",now);o.set("recovery",q.delivery.recovery);if(!provider.empty())o.set("providerId",provider);auto scopes=Poco::makeShared<Array>();for(auto &s:q.scopes)scopes->add(s);o.set("scopes",scopes);events_.push_back(o);if(events_.size()>1000)events_.erase(events_.begin());
}
void VenueAlertService::Tick(){
    using namespace VenueAlerts;
    {std::lock_guard lock(mutex_);if(!available_||std::none_of(policies_.begin(),policies_.end(),[](auto &p){return p.second.enabled;}))return;}
    auto suspend=[&](){std::lock_guard lock(mutex_);engine_.SuspendObservations(AlertNow());};
    std::map<std::string,ProvObjects::InventoryTag> inventory;
    for(uint64_t offset=0;offset<10000;offset+=500){InventoryDB::RecordVec page;if(!StorageService()->InventoryDB().GetRecords(offset,500,page,""," ORDER BY serialNumber ASC ")){suspend();return;}
        for(auto &d:page)if(d.subscriber.empty()&&(d.platform=="AP"||d.platform=="ap")&&(!d.venue.empty()||!d.entity.empty())&&UserAccess::ResolveStoredDevice(d.serialNumber).ownershipResolved)inventory[d.serialNumber]=d;if(page.size()<500)break;if(offset==9500){suspend();return;}}
    std::map<std::string,Object::Ptr> devices;
    bool complete=false;for(uint64_t offset=0;offset<10000;offset+=500){Object::Ptr response;OpenAPIRequestGet request(uSERVICE_GATEWAY,"/api/v1/devices",{{"deviceWithStatus","true"},{"platform","ap"},{"limit","500"},{"offset",std::to_string(offset)}},5000,"Alert device status read");
        if(request.Do(response)!=200||!response){suspend();return;}auto page=response->getArray("devicesWithStatus");if(!page){suspend();return;}for(size_t i=0;i<page->size();++i){auto d=page->getObject(i);if(!d){suspend();return;}auto serial=d->optValue<std::string>("serialNumber","");if(serial.empty()||devices.count(serial)){suspend();return;}devices[serial]=d;}if(page->size()<500){complete=true;break;}}
    if(!complete){suspend();return;}auto now=AlertNow();std::map<std::string,std::string> ownership;for(auto &[serial,d]:inventory)ownership[serial]=OwnerKey(d);
    {std::lock_guard lock(mutex_);engine_.RetainDevices(ownership);}
    for(auto &[serial,device]:inventory){if(!running_)break;auto owner=OwnerKey(device);auto scope=Owner(owner);auto found=devices.find(serial);auto connected=Observation::Unknown;
        if(found!=devices.end()&&found->second->has("connected")&&found->second->get("connected").type()==typeid(bool))connected=True(*found->second,"connected")?Observation::Healthy:Observation::Fault;
        Object::Ptr health;std::pair<Observation,Observation> healthState{Observation::Unknown,Observation::Unknown};
        bool needHealth=false;{std::lock_guard lock(mutex_);auto effective=Effective(scope.first,scope.second);if(!effective.second.enabled)continue;for(auto &rule:effective.second.rules)needHealth|=rule.enabled&&rule.type!="down";}
        if(connected==Observation::Healthy&&needHealth){OpenAPIRequestGet req(uSERVICE_GATEWAY,"/api/v1/device/"+serial+"/healthchecks",{{"newest","true"},{"limit","1"}},5000,"Alert health read");if(req.Do(health)==200)try{healthState=Health(health,now);}catch(...){}}
        std::lock_guard lock(mutex_);if(!available_)return;ProvObjects::InventoryTag current;if(!StorageService()->InventoryDB().GetRecord("serialNumber",serial,current)||OwnerKey(current)!=owner)continue;
        RefreshContext(owner);auto effective=Effective(scope.first,scope.second);auto policy=effective.second;if(!policy.enabled)continue;bool quiet=true;try{quiet=QuietNow(policy.quietHours,now);}catch(...){poco_warning(Logger(),"Alert quiet-hours timezone unavailable; delivery suppressed.");}
        auto lineage=Lineage(scope.first,scope.second);if(lineage.empty())continue;std::vector<std::string> scopes;std::string entity;
        for(auto &s:lineage){scopes.push_back(ScopeKey(s.type,s.id));if(s.type=="entity"&&entity.empty())entity=s.id;}
        for(auto &type:std::vector<std::string>{"down","critical","radio"}){auto observation=type=="down"?connected:type=="critical"?healthState.first:healthState.second;
            auto deliveries=engine_.Observe(owner,serial,type,observation,now,policy,quiet);
            for(auto &d:deliveries){Queued q;q.delivery=d;q.due=now+(d.channel=="email"?policy.groupWindowSeconds:0);q.deviceName=device.info.name.empty()?serial:device.info.name;q.venueName=scope.first=="venue"?ScopeName("venue",device.venue):"";q.entityName=ScopeName("entity",entity);q.scopes=scopes;
                q.group=d.channel+":"+d.recipient+":"+(policy.groupBy=="entity"||device.venue.empty()?"entity/"+entity:"venue/"+device.venue)+":"+std::to_string(policy.groupWindowSeconds)+(d.channel=="sms"?":"+d.id:"");
                for(auto &existing:queue_)if(existing.group==q.group&&!existing.dispatching&&engine_.HasReservation(existing.delivery))q.due=std::min(q.due,existing.due);
                queue_.push_back(q);Event(q,"queued",now);}
        }
    }
    {std::lock_guard lock(mutex_);if(!available_||!Persist())return;}Flush(AlertNow());
}
void VenueAlertService::Flush(int64_t now){
    using namespace VenueAlerts;
    std::string gatewayUI;Object::Ptr info;
    OpenAPIRequestGet uiRequest(uSERVICE_GATEWAY,"/api/v1/system",{{"command","info"}},5000,"Alert device link lookup");
    if(uiRequest.Do(info)==200&&info&&info->has("UI")&&info->get("UI").isString()){
        try{Poco::URI uri(info->getValue<std::string>("UI"));if((uri.getScheme()=="https"||uri.getScheme()=="http")&&!uri.getHost().empty()&&uri.getUserInfo().empty()){gatewayUI=uri.toString();while(!gatewayUI.empty()&&gatewayUI.back()=='/')gatewayUI.pop_back();}}catch(...){}
    }
    std::unique_lock lock(mutex_);if(!available_)return;
    std::set<std::string> owners;for(auto &q:queue_)owners.insert(q.delivery.venue);for(auto &owner:owners)RefreshContext(owner);
    for(auto it=queue_.begin();it!=queue_.end();){if(!engine_.HasReservation(it->delivery)){Event(*it,"cancelled",now);it=queue_.erase(it);}else ++it;}
    std::map<std::string,std::vector<std::string>> groups;
    for(size_t i=0;i<queue_.size();++i){auto &q=queue_[i];auto scope=Owner(q.delivery.venue);auto effective=Effective(scope.first,scope.second);bool quiet=true;try{quiet=QuietNow(effective.second.quietHours,now);}catch(...){}
        if(q.due<=now&&!quiet&&effective.second.muteUntil<=now&&engine_.IsPending(q.delivery))groups[q.group].push_back(q.delivery.id);}
    std::set<std::string> finished;
    for(auto &[key,indexes]:groups){if(!running_)break;
        // Recheck canonical venue ownership immediately before accepting work.
        std::vector<Queued> valid;
        for(auto &id:indexes){auto found=std::find_if(queue_.begin(),queue_.end(),[&](auto &q){return q.delivery.id==id;});if(found==queue_.end())continue;RefreshContext(found->delivery.venue);if(!engine_.IsPending(found->delivery))continue;
            auto &q=*found;ProvObjects::InventoryTag d;if(StorageService()->InventoryDB().GetRecord("serialNumber",q.delivery.serial,d)&&OwnerKey(d)==q.delivery.venue&&UserAccess::ResolveStoredDevice(d.serialNumber).ownershipResolved){if(valid.size()<12)valid.push_back(q);}
            else {engine_.Hold(q.delivery,now);Event(q,"cancelled",now);finished.insert(q.delivery.id);}}
        if(valid.empty())continue;
        auto &first=valid.front();std::string subject="OpenWiFi: "+std::to_string(valid.size())+(valid.size()==1?" device update":" device updates");
        std::string text="OpenWiFi device updates\n"+Date(now)+"\n\n";
        std::string html="<!doctype html><html><body style=\"margin:0;background:#f2f5f9;font-family:Arial,sans-serif;color:#203047\"><div style=\"max-width:680px;margin:24px auto;background:#fff;border-radius:10px;overflow:hidden\"><div style=\"background:#174e83;color:#fff;padding:24px\"><h1 style=\"margin:0;font-size:23px\">OpenWiFi alerts</h1><p style=\"margin-bottom:0\">"+Escape(Date(now))+"</p></div><div style=\"padding:24px\">";
        for(auto &q:valid){auto state=q.delivery.recovery?Label(q.delivery.type)+" cleared":Label(q.delivery.type);std::string link=gatewayUI.empty()?"":gatewayUI+"/#/devices/"+q.delivery.serial;
            auto site=q.entityName+(q.venueName.empty()?"":" / "+q.venueName);
            text+=site+"\n"+q.deviceName+" ("+q.delivery.serial+"): "+state+"\n"+(link.empty()?"":link+"\n")+"\n";
            html+="<div style=\"border:1px solid #dce4ed;border-left:4px solid "+std::string(q.delivery.recovery?"#21834d":"#c0392b")+";border-radius:6px;padding:16px;margin-bottom:14px\"><p style=\"margin:0;color:#52657a;font-size:13px\">"+Escape(site)+"</p><h2 style=\"font-size:18px;margin:8px 0\">"+Escape(q.deviceName)+"</h2><p style=\"margin:8px 0;font-weight:bold\">"+Escape(state)+"</p><p style=\"font-size:12px;color:#52657a\">"+Escape(q.delivery.serial)+"</p>"+(link.empty()?"":"<a style=\"color:#1764ac\" href=\""+Escape(link)+"\">View device</a>")+"</div>";
        }
        html+="<p style=\"font-size:12px;color:#63758a\">Sent according to your site alert rules.</p></div></div></body></html>";
        Object body;body.set("channel",first.delivery.channel);body.set("recipient",first.delivery.recipient);body.set("subject",subject);body.set("eventId",MicroServiceCreateUUID());
        if(first.delivery.channel=="sms")text="OpenWiFi: "+(first.venueName.empty()?first.entityName:first.venueName)+" / "+first.deviceName+": "+(first.delivery.recovery?Label(first.delivery.type)+" cleared":Label(first.delivery.type))+". "+Date(now);
        body.set("text",text);if(first.delivery.channel=="email")body.set("html",html);
        for(auto &q:valid){auto found=std::find_if(queue_.begin(),queue_.end(),[&](auto &p){return p.delivery.id==q.delivery.id;});if(found!=queue_.end())found->dispatching=true;Event(q,"dispatching",now);}if(!Persist())return;
        lock.unlock();Object::Ptr answer;OpenAPIRequestPost request(uSERVICE_SECURITY,"/api/v1/alertDelivery",{},body,20000,"Alert delivery");auto status=request.Do(answer);lock.lock();if(!available_)return;now=AlertNow();
        bool accepted=status==200&&answer&&True(*answer,"accepted");bool retryable=answer&&True(*answer,"retryable")&&!True(*answer,"ambiguous");
        for(auto &q:valid){if(accepted){engine_.Accept(q.delivery,now);Event(q,"accepted",now,answer->optValue<std::string>("providerId",""));}
            else if(retryable){engine_.Reject(q.delivery,now);Event(q,"retrying",now);}else{engine_.Hold(q.delivery,now);Event(q,status==504?"unknown":"failed",now);}finished.insert(q.delivery.id);}
        if(!Persist())return;
    }
    queue_.erase(std::remove_if(queue_.begin(),queue_.end(),[&](auto &q){return finished.count(q.delivery.id)>0;}),queue_.end());Persist();
}
bool HandleAlertSettings(RESTAPIHandler &handler,const std::string &kind,const std::string &id,bool update,const Poco::JSON::Object::Ptr &body){
    auto resource=UserAccess::ResolveStoredScope({kind,id});
    if(!resource.ownershipResolved){handler.NotFound();return false;}
    SecurityObjects::UserInfo current;
    if(!UserAccess::ReadCurrentUser(handler.AccessSubject().id,current)||!UserAccess::AllowsUser(current,resource,update?"resources.write":"devices.read")){handler.UnAuthorized(RESTAPI::Errors::ACCESS_DENIED);return false;}
    if(update){if(!body){handler.BadRequest(RESTAPI::Errors::InvalidJSONDocument);return false;}auto result=VenueAlertsService()->Save(kind,id,*body);
        if(result==VenueAlertService::Result::invalid){handler.BadRequest(RESTAPI::Errors::InvalidJSONDocument);return false;}if(result==VenueAlertService::Result::unavailable){handler.ReturnStatus(Poco::Net::HTTPResponse::HTTP_SERVICE_UNAVAILABLE);return false;}}
    auto out=VenueAlertsService()->Get(kind,id,current);handler.ReturnObject(out);return true;
}
} // namespace OpenWifi
