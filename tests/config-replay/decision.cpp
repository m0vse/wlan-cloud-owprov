#include "ConfigReplay.h"
#include <cassert>
#include <iostream>
using Json=nlohmann::json;
int main() {
 const std::string serial="aabbcc000001";
 Json desired={{"unit",{{"hostname","Synthetic AP"}}}};
 Json snapshot={{"deviceInfo",{{"serialNumber",serial},{"UUID",123},{"pendingUUID",0},{"pendingConfiguration",""},{"configuration",{{"uuid",123},{"unit",{{"hostname","Synthetic AP"}}}}}}},{"connectionInfo",{{"connected",true},{"UUID",123},{"connectReason","socket"}}}};
 unsigned checks=0;
 auto check=[&](Json state,bool skip,std::uint64_t version=123){auto actual=OpenWifi::ConfigReplay::Evaluate(serial,desired.dump(),state.dump());assert(actual.unchanged==skip);assert(actual.version==version);++checks;};
 check(snapshot,true);
 for (auto reason:{"unexpected-shutdown","upgrade","reboot","power-on","recovery","crashlog","upgradefailed","unknown"}) {auto state=snapshot;state["connectionInfo"]["connectReason"]=reason;check(state,false);}
 {auto state=snapshot;state["connectionInfo"].erase("connectReason");check(state,false);}
 {auto state=snapshot;state["connectionInfo"]["connectReason"]=nullptr;check(state,false);}
 {auto state=snapshot;state["connectionInfo"]["connectReason"]=17;check(state,false);}
 {auto state=snapshot;state["deviceInfo"]["configuration"]["unit"]["hostname"]="Old AP";check(state,false);}
 {auto state=snapshot;state["deviceInfo"]["pendingUUID"]=124;check(state,false,0);}
 {auto state=snapshot;state["connectionInfo"]["UUID"]=122;check(state,false,0);}
 {auto state=snapshot;state["connectionInfo"]["connected"]=false;check(state,false,0);}
 {auto state=snapshot;state["deviceInfo"]["serialNumber"]="aabbcc000002";check(state,false,0);}
 {auto state=snapshot;state["deviceInfo"]["configuration"]=state["deviceInfo"]["configuration"].dump();check(state,true);}
 for(int i=0;i<3;i++)check(snapshot,true);
 std::cout<<"PASS "<<checks<<" actual replay decision controls: fresh process acceptance, normal reconnect no-op, legacy fallback and pending/failed apply\n";
}
