/*
   ldb database library
   Copyright (C) Nadezhda Ivanova <nivanova@samba.org> 2017

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: ldb
 *
 *  Component: security token control module
 *
 *  Description:
 *  - A small module to send the security token as a control
 *  to the openldap backend.
 *  Only in use with OpenLDAP backend
 *  Author: Nadezhda Ivanova
 */
#include "includes.h"
#include "ldb.h"
#include <ldb_module.h>
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "libcli/security/security.h"
#include "dsdb/samdb/samdb.h"
#include "auth/auth.h"

static int sec_token_control_add_to_request(struct ldb_module *module, struct ldb_request *req)
{
	struct ldb_context *ldb = ldb_module_get_ctx(module);
	struct auth_session_info *session_info
		= ldb_get_opaque(ldb, "sessionInfo");
	int ret;

	ret = ldb_request_add_control(req,
				      DSDB_CONTROL_SEC_TOKEN_OID,
				      false, session_info->security_token);
	if (ret != LDB_SUCCESS) {
		return ldb_module_operr(module);
	}
	return ldb_next_request(module, req);
}

static const struct ldb_module_ops ldb_sec_token_control_module_ops = {
	.name          = "sec_token_control",
	.add           = sec_token_control_add_to_request,
	.modify        = sec_token_control_add_to_request,
	.del           = sec_token_control_add_to_request,
	.rename        = sec_token_control_add_to_request,
	.search        = sec_token_control_add_to_request,
};

int ldb_sec_token_control_init(const char *version)
{
	LDB_MODULE_CHECK_VERSION(version);
	return ldb_register_module(&ldb_sec_token_control_module_ops);
}
