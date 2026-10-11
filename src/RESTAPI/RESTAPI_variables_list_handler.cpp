//
// Created by stephane bourque on 2022-02-23.
//

#include "RESTAPI_variables_list_handler.h"
#include "ScopedRead.h"
#include "RESTAPI/RESTAPI_db_helpers.h"

namespace OpenWifi {

	void RESTAPI_variables_list_handler::DoGet() {
        if (ScopedReadList<VariablesDB>(DB_, *this, "variable", "variableBlocks")) return;
		return ListHandler<VariablesDB>("variableBlocks", DB_, *this);
	}

} // namespace OpenWifi
