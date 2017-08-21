/*
   Unix SMB/CIFS implementation.
   Samba utility functions

   Copyright (C) 2014 Nadezhda Ivanova <nivanova@samba.org>

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

#ifndef _LIBCLI_SAMBA_SECURITY_SECURITY_H_
#define _LIBCLI_SAMBA_SECURITY_SECURITY_H_
#include <stdbool.h>
#include <stdint.h>
#include <talloc.h>
#include "lib/util/data_blob.h"

typedef enum {
	SD_PARTITION_INVALID = 0,
	SD_PARTITION_SCHEMA,
	SD_PARTITION_CONFIG,
	SD_PARTITION_DEFAULT,
	SD_PARTITION_OTHER
} SD_PARTITION;

#define        SD_SECINFO_OWNER  0x00000001
#define        SD_SECINFO_GROUP  0x00000002
#define        SD_SECINFO_DACL   0x00000004
#define        SD_SECINFO_SACL   0x00000008

/* returns the appropriate parts of a security descriptor as requested by
 * the supplied value of sdflags control */
DATA_BLOB *security_descriptor_ds_get_sd_to_display(TALLOC_CTX *mem_ctx,
						    const DATA_BLOB *sd,
						    uint32_t sd_flags);

/* creates the appropriate security descriptor for a newly created or
   renamed object */
DATA_BLOB *security_descriptor_ds_create_as_blob(TALLOC_CTX *mem_ctx,
						 const DATA_BLOB *blob_token,
						 const DATA_BLOB *blob_domain_sid,
						 const char *defaultSecurityDescriptor,
						 const DATA_BLOB *schemaIDGUID,
						 const DATA_BLOB *parent,
						 const DATA_BLOB *object,
						 const DATA_BLOB *old_sd,
						 SD_PARTITION partition,
						 uint32_t sd_flags,
						 char **out_as_sddl);


#endif
