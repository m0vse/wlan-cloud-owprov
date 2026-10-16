#include "VenueAlertQuietHours.h"
#include <cassert>
#include <cstdlib>
#include <iostream>
#include <sstream>
#ifdef VENUE_ALERT_TEST_POCO
#include "VenueAlertJSON.h"
#include <Poco/JSON/Parser.h>
#endif
using namespace OpenWifi::VenueAlerts;
static int64_t UTC(int year,int month,int day,int hour,int minute=0,int second=0) {
    std::tm tm{};tm.tm_year=year-1900;tm.tm_mon=month-1;tm.tm_mday=day;tm.tm_hour=hour;tm.tm_min=minute;tm.tm_sec=second;
    return timegm(&tm);
}
template<class F> static void Invalid(F f) {bool invalid=false;try{f();}catch(const std::exception &){invalid=true;}assert(invalid);}
#ifdef VENUE_ALERT_TEST_POCO
static Object::Ptr JSON(const std::string &s) {Poco::JSON::Parser p;return p.parse(s).extract<Object::Ptr>();}
static Object::Ptr Wire(const Object &o) {std::ostringstream out;o.stringify(out);return JSON(out.str());}
static const std::string valid=R"({"enabled":true,"emails":["one@example.org"],"phones":["+447700900123"],"rules":[{"type":"down","enabled":true,"delaySeconds":300,"recoveryDelaySeconds":60,"repeatSeconds":0,"recovery":true,"email":true,"sms":false}],"quietHours":{"enabled":true,"timezone":"Europe/London","start":"22:00","end":"08:00","days":[1,2,3,4,5,6,7]},"muteUntil":0,"groupBy":"venue","groupWindowSeconds":60})";
#endif
int main() {
    int controls=0;
    const auto tz=std::getenv("TZ");const std::string original=tz?tz:"";const bool hadTZ=tz!=nullptr;
    {assert(ZoneOffset("Europe/London",UTC(2026,1,15,12))==0);assert(ZoneOffset("Europe/London",UTC(2026,7,15,12))==3600);assert(ZoneOffset("UTC",UTC(2026,7,15,12))==0);controls++;}
    {auto t=UTC(2026,3,29,1);assert(ZoneOffset("Europe/London",t-1)==0);assert(ZoneOffset("Europe/London",t)==3600);t=UTC(2026,10,25,1);assert(ZoneOffset("Europe/London",t-1)==3600);assert(ZoneOffset("Europe/London",t)==0);controls++;}
    {QuietHours q;q.enabled=true;q.start="09:00";q.end="10:00";assert(QuietNow(q,UTC(2026,7,15,8)));assert(!QuietNow(q,UTC(2026,7,15,9)));assert(!QuietNow(q,UTC(2026,1,15,8)));assert(QuietNow(q,UTC(2026,1,15,9)));controls++;}
    {QuietHours q;q.enabled=true;q.days={1};assert(QuietNow(q,UTC(2026,10,19,21)));assert(QuietNow(q,UTC(2026,10,20,6,59)));assert(!QuietNow(q,UTC(2026,10,20,7)));assert(!QuietNow(q,UTC(2026,10,20,21)));controls++;}
    {QuietHours q;q.enabled=true;q.start="01:00";q.end="02:00";assert(!QuietNow(q,UTC(2026,3,29,0,59)));assert(!QuietNow(q,UTC(2026,3,29,1)));assert(QuietNow(q,UTC(2026,10,25,0,30)));assert(QuietNow(q,UTC(2026,10,25,1,30)));controls++;}
    {QuietHours q;q.enabled=true;q.timezone="UTC";q.start=q.end="12:00";q.days={7};assert(QuietNow(q,UTC(2026,10,18,0)));assert(QuietNow(q,UTC(2026,10,18,23,59)));assert(!QuietNow(q,UTC(2026,10,19,0)));q.enabled=false;assert(!QuietNow(q,UTC(2026,10,18,0)));controls++;}
    {for(const auto &zone:{"", "../etc/passwd", "/etc/passwd", "Europe/NotAnIanaZone", "Europe/London\n", "Etc/../../etc/passwd"}) Invalid([&]{ZoneOffset(zone,UTC(2026,10,16,0));});controls++;}
    {std::vector<unsigned char> b(50,0);b[0]='T';b[1]='Z';b[2]='i';b[3]='f';b[39]=1;assert(ZoneOffsetBytes(b,0)==0);auto truncated=b;truncated.pop_back();Invalid([&]{ZoneOffsetBytes(truncated,0);});auto bad=b;bad[0]='x';Invalid([&]{ZoneOffsetBytes(bad,0);});bad=b;bad[20]=255;Invalid([&]{ZoneOffsetBytes(bad,0);});bad=b;bad[39]=0;Invalid([&]{ZoneOffsetBytes(bad,0);});bad=b;bad[4]='2';Invalid([&]{ZoneOffsetBytes(bad,0);});bad=b;bad[44]=127;Invalid([&]{ZoneOffsetBytes(bad,0);});Invalid([&]{ZoneOffsetBytes(std::vector<unsigned char>(1024*1024+1),0);});controls++;}
    {auto after=std::getenv("TZ");assert((after!=nullptr)==hadTZ);assert((after?std::string(after):"")==original);controls++;}
#ifdef VENUE_ALERT_TEST_POCO
    {auto p=ParsePolicy(*JSON(valid));auto result=ParsePolicy(*Wire(PolicyJSON(p)));assert(result.enabled && result.emails==p.emails && result.phones==p.phones && result.rules.size()==1 && result.quietHours.timezone=="Europe/London" && result.groupBy=="venue" && result.groupWindowSeconds==60);controls++;}
    {for(auto value:{"true","\"1\"","1.0","null"}) {auto o=JSON(valid);o->set("muteUntil",JSON(std::string("{\"v\":")+value+"}")->get("v"));Invalid([&]{ParsePolicy(*o);});}controls++;}
    {auto o=JSON(valid);o->set("enabled",1);Invalid([&]{ParsePolicy(*o);});o=JSON(valid);o->set("enabled","true");Invalid([&]{ParsePolicy(*o);});o=JSON(valid);o->remove("enabled");Invalid([&]{ParsePolicy(*o);});controls++;}
    {auto o=JSON(valid);o->set("arbitraryEndpoint","https://example.org");Invalid([&]{ParsePolicy(*o);});o=JSON(valid);o->getObject("quietHours")->set("surprise",true);Invalid([&]{ParsePolicy(*o);});o=JSON(valid);o->getArray("rules")->getObject(0)->set("surprise",true);Invalid([&]{ParsePolicy(*o);});controls++;}
    {auto o=JSON(valid);o->getArray("rules")->getObject(0)->set("delaySeconds",INT64_C(4294967296));Invalid([&]{ParsePolicy(*o);});o=JSON(valid);o->getObject("quietHours")->getArray("days")->set(0,true);Invalid([&]{ParsePolicy(*o);});o=JSON(valid);o->getArray("emails")->set(0,123);Invalid([&]{ParsePolicy(*o);});controls++;}
    {Engine e;auto p=ParsePolicy(*JSON(valid));p.quietHours.enabled=false;p.rules[0].delaySeconds=0;auto d=e.Observe("venue","ap","down",Observation::Fault,100,p);assert(d.size()==1);auto decoded=ParseDelivery(*Wire(DeliveryJSON(d[0])));assert(decoded.id==d[0].id && decoded.key==d[0].key && decoded.recipient==d[0].recipient && decoded.recovery==d[0].recovery);auto s=ParseSnapshot(*Wire(SnapshotJSON(e.Save())));assert(s.sequence==e.Save().sequence && s.alerts.size()==1 && s.alerts.begin()->second.recipients.begin()->second.pendingId==d[0].id);e.Hold(d[0],100);s=ParseSnapshot(*Wire(SnapshotJSON(e.Save())));assert(s.alerts.begin()->second.recipients.begin()->second.held);Engine restored;restored.Restore(s);assert(restored.Observe("venue","ap","down",Observation::Fault,1000,p).empty());controls++;}
    {auto p=ParsePolicy(*JSON(valid));p.rules[0].delaySeconds=0;p.quietHours.enabled=false;Engine e;auto d=e.Observe("v","s","down",Observation::Fault,0,p);e.Accept(d[0],0);auto s=ParseSnapshot(*Wire(SnapshotJSON(e.Save())));Engine restored;restored.Restore(s);assert(restored.Observe("v","s","down",Observation::Healthy,1000,p).empty());auto r=restored.Observe("v","s","down",Observation::Healthy,1060,p);assert(r.size()==1 && r[0].recovery);controls++;}
    {auto p=ParsePolicy(*JSON(valid));p.rules[0].delaySeconds=0;Engine e;auto d=e.Observe("v","s","down",Observation::Fault,0,p);auto invalid=[&](auto mutate){auto o=Wire(DeliveryJSON(d[0]));mutate(*o);Invalid([&]{ParseDelivery(*o);});};invalid([](auto &o){o.set("surprise",true);});invalid([](auto &o){o.set("channel","webhook");});invalid([](auto &o){o.set("key","forged");});invalid([](auto &o){o.set("id","-1");});invalid([](auto &o){o.set("recovery",1);});controls++;}
    {auto p=ParsePolicy(*JSON(valid));p.rules[0].delaySeconds=0;Engine e;e.Observe("v","s","down",Observation::Fault,0,p);auto invalid=[&](auto mutate){auto o=Wire(SnapshotJSON(e.Save()));mutate(*o);Invalid([&]{ParseSnapshot(*o);});};invalid([](auto &o){o.set("sequence",-1);});invalid([](auto &o){o.set("surprise",true);});invalid([](auto &o){o.getArray("alerts")->getObject(0)->set("elapsed",-1);});invalid([](auto &o){o.getArray("alerts")->getObject(0)->set("lastObserved",-2);});invalid([](auto &o){o.getArray("alerts")->getObject(0)->set("phase",3);});invalid([](auto &o){o.getArray("alerts")->getObject(0)->set("key","forged");});invalid([](auto &o){auto a=o.getArray("alerts");a->add(*a->getObject(0));});controls++;}
    {auto p=ParsePolicy(*JSON(valid));p.rules[0].delaySeconds=0;Engine e;e.Observe("v","s","down",Observation::Fault,0,p);auto o=Wire(SnapshotJSON(e.Save()));auto recipients=o->getArray("alerts")->getObject(0)->getObject("recipients");auto r=recipients->getObject("email:one@example.org");r->remove("held");auto parsed=ParseSnapshot(*o);assert(!parsed.alerts.begin()->second.recipients.begin()->second.held);r->set("lastAttempt",-2);Invalid([&]{ParseSnapshot(*o);});controls++;}
#else
    std::cout<<"Poco codec controls NOT RUN (build with VENUE_ALERT_TEST_POCO)\n";
#endif
    std::cout<<controls<<" venue alert integration controls PASS\n";
}
