#pragma once
#include "framework/RESTAPI_Handler.h"

namespace OpenWifi {
class RESTAPI_access_check_handler : public RESTAPIHandler {
public:
    RESTAPI_access_check_handler(const BindingMap &bindings, Poco::Logger &logger,
            RESTAPI_GenericServerAccounting &server, uint64_t transactionId, bool internal)
        : RESTAPIHandler(bindings, logger, {Poco::Net::HTTPRequest::HTTP_POST},
                         server, transactionId, internal) {}
    static auto PathName() { return std::list<std::string>{"/api/v1/access/check"}; }
private:
    void DoPost() final;
    void DoGet() final {}
    void DoPut() final {}
    void DoDelete() final {}
};
}
