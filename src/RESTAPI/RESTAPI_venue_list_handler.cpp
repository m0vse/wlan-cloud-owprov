//
// Created by stephane bourque on 2021-08-23.
//

#include "RESTAPI_venue_list_handler.h"
#include "RESTAPI/RESTAPI_db_helpers.h"
#include "StorageService.h"
#include "ScopedRead.h"

namespace OpenWifi {
	void RESTAPI_venue_list_handler::DoGet() {
        if (ScopedReadList<VenueDB>(DB_, *this, "venue", "venues")) return;
        auto RRMvendor = GetParameter("RRMvendor","");
        if(RRMvendor.empty()) {
            return ListHandler<VenueDB>("venues", DB_, *this);
        }
        VenueDB::RecordVec Venues;
        auto Where = fmt::format(" deviceRules LIKE '%{}%' ", RRMvendor);
        DB_.GetRecords(QB_.Offset, QB_.Limit, Venues, Where, " ORDER BY name ");
        return ReturnObject("venues",Venues);
    }
} // namespace OpenWifi
