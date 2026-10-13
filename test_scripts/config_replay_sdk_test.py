#!/usr/bin/env python3
"""Exercise the actual Configure method with real Poco JSON and fake HTTP boundaries.

Run inside the existing build SDK; no service/AP/network changes are made.
The method is extracted verbatim so tests cannot silently substitute its logic.
"""
from pathlib import Path
import os, subprocess, tempfile

root = Path(__file__).resolve().parents[1]
source = (root / 'src/sdks/SDK_gw.cpp').read_text()
start = source.index('\t\tbool Configure(')
end = source.index('\n\t} // namespace Device', start)
method = source[start:end]
discovery = (root / 'src/AutoDiscovery.cpp').read_text()
assert 'ComputeAndPushConfig(SerialNumber, Compatible, Logger(), true);' in discovery
header = (root / 'src/sdks/SDK_gw.h').read_text()
assert 'bool Reconnect=false' in header or 'bool Reconnect = false' in header

prefix = r'''
#include "ConfigReplay.h"
#include <Poco/JSON/Object.h>
#include <Poco/JSON/Parser.h>
#include <Poco/JSON/Stringifier.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/SharedPtr.h>
#include <algorithm>
#include <limits>
#include <sstream>
#include <iostream>
#include <stdexcept>
namespace OpenWifi {
const char* uSERVICE_GATEWAY="owgw";
struct RESTAPIHandler { struct { struct { std::string access_token_; } webtoken; } UserInfo_; };
namespace Utils { uint64_t Now(){return 100;} }
int reads=0,posts=0,getStatus=200,postStatus=200; bool throwRead=false;
std::string state,auth; Poco::JSON::Object sent;
struct OpenAPIRequestGet {
 OpenAPIRequestGet(const char*,const std::string& path,const std::vector<std::pair<std::string,std::string>>& query,int timeout){
  if(path!="/api/v1/device/001122334455" || query!=std::vector<std::pair<std::string,std::string>>{{"completeInfo","true"}} || timeout!=10000)throw std::runtime_error("GET contract");
 }
 int Do(Poco::JSON::Object::Ptr& result){reads++;if(throwRead)throw std::runtime_error("unavailable");if(getStatus==200)result=Poco::JSON::Parser().parse(state).extract<Poco::JSON::Object::Ptr>();return getStatus;}
};
struct OpenAPIRequestPost {
 OpenAPIRequestPost(const char*,const std::string& path,const std::vector<std::pair<std::string,std::string>>&,const Poco::JSON::Object& body,int timeout){
  if(path!="/api/v1/device/001122334455/configure" || timeout!=60000)throw std::runtime_error("POST contract");sent=body;
 }
 int Do(Poco::JSON::Object::Ptr& response,const std::string& token){posts++;auth=token;response=Poco::makeShared<Poco::JSON::Object>();return postStatus;}
};
namespace SDK::GW::Device {
'''
suffix = r'''
}} // namespaces
int main(){
 using namespace OpenWifi; using J=nlohmann::json;
 J desired={{"unit",{{"hostname","fixture"}}}};
 J config=desired;config["uuid"]=123;
 J snapshot={{"deviceInfo",{{"serialNumber","001122334455"},{"UUID",123},{"configuration",config},{"pendingUUID",0},{"pendingConfiguration",""}}},{"connectionInfo",{{"UUID",123},{"connected",true}}}};
 unsigned checks=0;auto check=[&](bool good){checks++;if(!good)throw std::runtime_error("SDK check "+std::to_string(checks));};
 auto run=[&](J d,J s,bool reconnect,RESTAPIHandler* client=nullptr){
  reads=posts=0;state=s.dump();auth="";
  auto c=Poco::JSON::Parser().parse(d.dump()).extract<Poco::JSON::Object::Ptr>();
  auto r=Poco::makeShared<Poco::JSON::Object>();
  bool ok=SDK::GW::Device::Configure(client,"001122334455",c,r,reconnect);
  return std::make_pair(ok,r);
 };
 auto result=run(desired,snapshot,true);check(result.first);check(reads==1 && posts==0);check(result.second->getValue<uint64_t>("UUID")==123);check(result.second->getValue<bool>("unchanged"));
 auto reordered=desired;reordered["uuid"]=999;run(reordered,snapshot,true);check(posts==0);
 auto changed=desired;changed["unit"]["hostname"]="changed";run(changed,snapshot,true);check(reads==1 && posts==1);check(sent.getValue<uint64_t>("UUID")==124);check(sent.getObject("configuration")->getValue<uint64_t>("uuid")==124);
 auto failed=snapshot;failed["connectionInfo"]["UUID"]=122;run(desired,failed,true);check(posts==1);
 auto pending=snapshot;pending["deviceInfo"]["pendingUUID"]=124;run(desired,pending,true);check(posts==1);
 run(desired,snapshot,false);check(reads==0 && posts==1);
 RESTAPIHandler operatorClient;operatorClient.UserInfo_.webtoken.access_token_="synthetic-scoped-token";
 run(desired,snapshot,true,&operatorClient);check(reads==0 && posts==1);check(auth=="synthetic-scoped-token");
 getStatus=503;run(desired,snapshot,true);check(reads==1 && posts==1);getStatus=200;
 throwRead=true;run(desired,snapshot,true);check(reads==1 && posts==1);throwRead=false;
 postStatus=403;check(!run(changed,snapshot,true,&operatorClient).first);check(auth=="synthetic-scoped-token");
 std::cout<<"PASS "<<checks<<" actual Configure send/version/retry/manual-token controls; reconnect caller wired\n";
}
'''
with tempfile.TemporaryDirectory(prefix='config-replay-sdk-') as temp:
    cpp = Path(temp)/'test.cpp'; binary = Path(temp)/'test'
    cpp.write_text(prefix + method + suffix)
    subprocess.run(['g++','-std=c++20','-I'+str(root/'src'),'-I/usr/local/include',
                    '-I/vcpkg/installed/x64-linux/include',str(cpp),'-L/usr/local/lib',
                    '-Wl,-rpath,/usr/local/lib','-lPocoJSON','-lPocoNet','-lPocoFoundation',
                    '-o',str(binary)],check=True)
    subprocess.run([str(binary)],check=True)
