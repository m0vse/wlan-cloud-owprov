#include "ConfigReplay.h"
#include <iostream>
#include <stdexcept>
using J=nlohmann::json;
int main(){unsigned n=0;auto check=[&](bool v){if(!v)throw std::runtime_error("config replay check "+std::to_string(n));n++;};
J desired={{"unit",{{"hostname","fixture-ap"}}},{"interfaces",J::array({{{"name","LAN"},{"ssids",J::array({{{"name","Fixture"},{"encryption",{{"key","synthetic-key"}}}}})}}})}};
J current=desired;current["uuid"]=123;
J state={{"deviceInfo",{{"serialNumber","001122334455"},{"UUID",123},{"configuration",current},{"pendingUUID",0},{"pendingConfiguration",""}}},{"connectionInfo",{{"connected",true},{"UUID",123}}}};
auto run=[&](const J& d,const J& s){return OpenWifi::ConfigReplay::Evaluate("001122334455",d.dump(),s.dump());};
check(run(desired,state).unchanged);check(run(desired,state).version==123);
auto newId=desired;newId["uuid"]=456;check(run(newId,state).unchanged);
check(OpenWifi::ConfigReplay::Evaluate("001122334455",R"({"interfaces":[{"ssids":[{"encryption":{"key":"synthetic-key"},"name":"Fixture"}],"name":"LAN"}],"unit":{"hostname":"fixture-ap"}})",state.dump()).unchanged);
auto serialized=state;serialized["deviceInfo"]["configuration"]=current.dump();check(run(desired,serialized).unchanged);
for(const char* field:{"hostname","timezone"}){auto changed=desired;changed["unit"][field]="changed";check(!run(changed,state).unchanged);}
auto key=desired;key["interfaces"][0]["ssids"][0]["encryption"]["key"]="changed-key";check(!run(key,state).unchanged);
auto nested=desired;nested["unit"]["uuid"]=123;check(!run(nested,state).unchanged);
auto arr=desired;arr["interfaces"].push_back({{"name","second"}});check(!run(arr,state).unchanged);
for(const char* field:{"configuration","UUID","pendingConfiguration","pendingUUID","serialNumber"}){auto missing=state;missing["deviceInfo"].erase(field);check(!run(desired,missing).unchanged);}
auto pending=state;pending["deviceInfo"]["pendingConfiguration"]="{}";check(!run(desired,pending).unchanged);
pending=state;pending["deviceInfo"]["pendingUUID"]=124;check(!run(desired,pending).unchanged);
auto failed=state;failed["connectionInfo"]["UUID"]=122;check(!run(desired,failed).unchanged);
failed=state;failed["deviceInfo"]["UUID"]=122;check(!run(desired,failed).unchanged);
auto offline=state;offline["connectionInfo"]["connected"]=false;check(!run(desired,offline).unchanged);
offline=state;offline["connectionInfo"]["connected"]="true";check(!run(desired,offline).unchanged);
auto other=state;other["deviceInfo"]["serialNumber"]="another";check(!run(desired,other).unchanged);
auto malformed=state;malformed["deviceInfo"]["configuration"]="invalid JSON";check(!run(desired,malformed).unchanged);
check(!run(J::object(),state).unchanged);check(!run(desired,J::object()).unchanged);
auto noId=state;noId["deviceInfo"]["configuration"].erase("uuid");check(!run(desired,noId).unchanged);
auto zero=state;zero["deviceInfo"]["configuration"]["uuid"]=0;check(!run(desired,zero).unchanged);
auto boolId=state;boolId["deviceInfo"]["configuration"]["uuid"]=true;check(!run(desired,boolId).unchanged);
auto conflict=desired;conflict["uuid"]=123;conflict["unit"]["hostname"]="different";check(!run(conflict,state).unchanged);
check(!OpenWifi::ConfigReplay::Evaluate("001122334455","invalid",state.dump()).unchanged);
auto empty=state;empty["deviceInfo"]["configuration"]={{"uuid",123}};check(!run(J{{"uuid",456}},empty).unchanged);
std::cout<<"PASS "<<n<<" semantic configuration / active-version / pending-failure controls\n";
}
