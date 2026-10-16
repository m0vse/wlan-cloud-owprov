#pragma once
#include "VenueAlertJSON.h"
#include "framework/SubSystemServer.h"
#include "framework/RESTAPI_Handler.h"
#include <Poco/Runnable.h>
#include <Poco/Thread.h>
#include <atomic>
#include <mutex>

namespace OpenWifi {
class VenueAlertService : public SubSystemServer,public Poco::Runnable {
public:
    static VenueAlertService *instance(){static auto *p=new VenueAlertService;return p;}
    int Start() override;
    void Stop() override;
    void run() override;
    Poco::JSON::Object Get(const std::string &kind,const std::string &id,const SecurityObjects::UserInfo &user);
    enum class Result {saved,invalid,unavailable};
    Result Save(const std::string &kind,const std::string &id,const Poco::JSON::Object &body);
private:
    VenueAlertService():SubSystemServer("VenueAlerts","VENUE-ALERTS","venuealerts"){}
    struct Queued {VenueAlerts::Delivery delivery;int64_t due=0;bool dispatching=false;std::string group,deviceName,venueName,entityName;std::vector<std::string> scopes;};
    std::mutex mutex_;std::atomic_bool running_{false};Poco::Thread thread_;
    std::string path_;bool available_=false;std::map<std::string,VenueAlerts::Policy> policies_;
    std::map<std::string,std::string> contexts_;
    VenueAlerts::Engine engine_;std::vector<Queued> queue_;std::vector<Poco::JSON::Object> events_;
    bool Persist();void Load();void Tick();void Flush(int64_t now);
    std::pair<std::string,VenueAlerts::Policy> Effective(const std::string &kind,const std::string &id);
    void RefreshContext(const std::string &owner);
    void Event(const Queued &q,const std::string &status,int64_t now,const std::string &providerId="");
};
inline VenueAlertService *VenueAlertsService(){return VenueAlertService::instance();}
bool HandleAlertSettings(RESTAPIHandler &handler,const std::string &kind,const std::string &id,bool update,const Poco::JSON::Object::Ptr &body={});
} // namespace OpenWifi
