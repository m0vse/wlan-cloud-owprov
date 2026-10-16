#pragma once
#include "VenueAlertPolicy.h"
#include <algorithm>
#include <fstream>
#include <iterator>
#include <limits>
#include <ctime>
#include <stdexcept>

namespace OpenWifi::VenueAlerts {
// Read system IANA TZif data without changing process-global TZ or libc state.
// Quiet hours crossing midnight belong to the weekday on which they start.
inline int ZoneOffsetBytes(const std::vector<unsigned char> &b,int64_t now) {
    if(b.size()<44||b.size()>1024*1024)throw std::invalid_argument("timezone size");
    auto number=[&](size_t pos,size_t bytes)->uint64_t{if(pos+bytes>b.size())throw std::invalid_argument("timezone bounds");uint64_t n=0;for(size_t i=0;i<bytes;++i)n=(n<<8)|b[pos+i];return n;};
    auto counts=[&](size_t h){if(h+44>b.size()||std::string(b.begin()+h,b.begin()+h+4)!="TZif")throw std::invalid_argument("timezone header");std::vector<size_t> c;for(int i=0;i<6;++i){auto n=number(h+20+i*4,4);if(n>100000)throw std::invalid_argument("timezone count");c.push_back(n);}return c;};
    size_t h=0,width=4;auto c=counts(h);
    if(b[4]=='2'||b[4]=='3'||b[4]=='4'){h=44+c[3]*5+c[4]*6+c[5]+c[2]*8+c[0]+c[1];c=counts(h);width=8;}
    if(!c[4]||c[4]>256)throw std::invalid_argument("timezone types");
    size_t times=h+44,indexes=times+c[3]*width,types=indexes+c[3];
    if(types+c[4]*6+c[5]>b.size())throw std::invalid_argument("timezone truncated");
    auto instant=[&](size_t i){auto n=number(times+i*width,width);return width==4?int64_t(static_cast<int32_t>(n)):static_cast<int64_t>(n);};
    size_t type=0;for(size_t i=0;i<c[3];++i){if(instant(i)>now)break;type=b[indexes+i];}
    if(type>=c[4])throw std::invalid_argument("timezone type");
    // Do not silently extrapolate DST indefinitely past the supplied transitions.
    if(c[3]&&now>instant(c[3]-1)+366LL*86400){
        bool changing=false;for(size_t i=1;i<c[4];++i)changing|=number(types+i*6,4)!=number(types,4);
        if(changing)throw std::invalid_argument("timezone transitions need update");
    }
    auto offset=static_cast<int32_t>(number(types+type*6,4));
    if(offset < -86400||offset>86400)throw std::invalid_argument("timezone offset");
    return offset;
}
inline int ZoneOffset(const std::string &zone,int64_t now) {
    Policy validated;validated.quietHours.timezone=zone;Validate(validated);
    std::ifstream f("/usr/share/zoneinfo/"+zone,std::ios::binary);
    if(!f)throw std::invalid_argument("timezone unavailable");
    std::vector<unsigned char> b((std::istreambuf_iterator<char>(f)),{});
    return ZoneOffsetBytes(b,now);
}
inline bool QuietNow(const QuietHours &q,int64_t now) {
    if(!q.enabled)return false;
    auto local=static_cast<time_t>(now+ZoneOffset(q.timezone,now));std::tm tm{};
    if(!gmtime_r(&local,&tm))throw std::invalid_argument("quiet date");
    int minute=tm.tm_hour*60+tm.tm_min,start=std::stoi(q.start.substr(0,2))*60+std::stoi(q.start.substr(3)),end=std::stoi(q.end.substr(0,2))*60+std::stoi(q.end.substr(3));
    int day=tm.tm_wday==0?7:tm.tm_wday;
    if(start>end&&minute<end)day=day==1?7:day-1;
    bool scheduled=std::find(q.days.begin(),q.days.end(),day)!=q.days.end();
    return scheduled&&(start==end || (start<end?(minute>=start&&minute<end):(minute>=start||minute<end)));
}
} // namespace OpenWifi::VenueAlerts
