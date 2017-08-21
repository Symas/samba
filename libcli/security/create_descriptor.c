/*
   Copyright (C) Nadezhda Ivanova 2009

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
 *  Name: create_descriptor
 *
 *  Component: routines for calculating and creating security descriptors
 *  as described in MS-DTYP 2.5.3.x
 *
 *  Description:
 *
 *
 *  Author: Nadezhda Ivanova
 */
#include "includes.h"
#include "libcli/security/security.h"
#include "librpc/gen_ndr/ndr_security.h"
#include "librpc/gen_ndr/ndr_misc.h"

/* Todos:
 * build the security token dacl as follows:
 * SYSTEM: GA, OWNER: GA, LOGIN_SID:GW|GE
 * Need session id information for the login SID. Probably
 * the best place for this is during token creation
 *
 * Implement SD Invariants
 * ACE sorting rules
 * LDAP_SERVER_SD_FLAGS_OID control
 * ADTS 7.1.3.3 needs to be clarified
 */

/* the mapping function for generic rights for DS.(GA,GR,GW,GX)
 * The mapping function is passed as an argument to the
 * descriptor calculating routine and depends on the security
 * manager that calls the calculating routine.
 * TODO: need similar mappings for the file system and
 * registry security managers in order to make this code
 * generic for all security managers
 */

uint32_t security_descriptor_ds_map_generic_rights(uint32_t access_mask)
{
	if (access_mask & SEC_GENERIC_ALL) {
		access_mask |= SEC_ADS_GENERIC_ALL;
		access_mask &= ~SEC_GENERIC_ALL;
	}

	if (access_mask & SEC_GENERIC_EXECUTE) {
		access_mask |= SEC_ADS_GENERIC_EXECUTE;
		access_mask &= ~SEC_GENERIC_EXECUTE;
	}

	if (access_mask & SEC_GENERIC_WRITE) {
		access_mask |= SEC_ADS_GENERIC_WRITE;
		access_mask &= ~SEC_GENERIC_WRITE;
	}

	if (access_mask & SEC_GENERIC_READ) {
		access_mask |= SEC_ADS_GENERIC_READ;
		access_mask &= ~SEC_GENERIC_READ;
	}

	return access_mask;
}

/* Not sure what this has to be,
* and it does not seem to have any influence */
static bool object_in_list(struct GUID *object_list, struct GUID *object)
{
	size_t i;

	if (object_list == NULL) {
		return true;
	}

	if (GUID_all_zero(object)) {
		return true;
	}

	for (i=0; ; i++) {
		if (GUID_all_zero(&object_list[i])) {
			return false;
		}
		if (!GUID_equal(&object_list[i], object)) {
			continue;
		}

		return true;
	}

	return false;
}

/* returns true if the ACE gontains generic information
 * that needs to be processed additionally */
 
static bool desc_ace_has_generic(struct security_ace *ace)
{
	if (ace->access_mask & SEC_GENERIC_ALL || ace->access_mask & SEC_GENERIC_READ ||
	    ace->access_mask & SEC_GENERIC_WRITE || ace->access_mask & SEC_GENERIC_EXECUTE) {
		return true;
	}
	if (dom_sid_equal(&ace->trustee, &global_sid_Creator_Owner) ||
	    dom_sid_equal(&ace->trustee, &global_sid_Creator_Group)) {
		return true;
	}
	return false;
}

/* creates an ace in which the generic information is expanded */

static void security_ace_expand_generic_rights(struct security_ace *new_ace,
				struct dom_sid *owner,
				struct dom_sid *group)
{
	new_ace->access_mask = security_descriptor_ds_map_generic_rights(new_ace->access_mask);
	if (dom_sid_equal(&new_ace->trustee, &global_sid_Creator_Owner)) {
		new_ace->trustee = *owner;
	}
	if (dom_sid_equal(&new_ace->trustee, &global_sid_Creator_Group)) {
		new_ace->trustee = *group;
	}
	new_ace->flags = 0x0;
}

static struct security_acl *calculate_inherited_from_parent(TALLOC_CTX *mem_ctx,
							    struct security_acl *acl,
							    bool is_container,
							    struct dom_sid *owner,
							    struct dom_sid *group,
							    struct GUID *object_list)
{
	uint32_t i;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct security_acl *tmp_acl = talloc_zero(mem_ctx, struct security_acl);
	if (!tmp_acl) {
		return NULL;
	}

	if (!acl) {
		return NULL;
	}

	for (i=0; i < acl->num_aces; i++) {
		struct security_ace *ace = &acl->aces[i];
		if ((ace->flags & SEC_ACE_FLAG_CONTAINER_INHERIT) ||
		    (ace->flags & SEC_ACE_FLAG_OBJECT_INHERIT)) {
			struct GUID inherited_object = GUID_zero();

			tmp_acl->aces = talloc_realloc(tmp_acl, tmp_acl->aces,
						       struct security_ace,
						       tmp_acl->num_aces+1);
			if (tmp_acl->aces == NULL) {
				talloc_free(tmp_ctx);
				return NULL;
			}

			tmp_acl->aces[tmp_acl->num_aces] = *ace;
			tmp_acl->aces[tmp_acl->num_aces].flags |= SEC_ACE_FLAG_INHERITED_ACE;
			/* remove IO flag from the child's ace */
			if (ace->flags & SEC_ACE_FLAG_INHERIT_ONLY &&
			    !desc_ace_has_generic(ace)) {
				tmp_acl->aces[tmp_acl->num_aces].flags &= ~SEC_ACE_FLAG_INHERIT_ONLY;
			}

			if (is_container && (ace->flags & SEC_ACE_FLAG_OBJECT_INHERIT))
			    tmp_acl->aces[tmp_acl->num_aces].flags |= SEC_ACE_FLAG_INHERIT_ONLY;

			switch (ace->type) {
			case SEC_ACE_TYPE_ACCESS_ALLOWED:
			case SEC_ACE_TYPE_ACCESS_DENIED:
			case SEC_ACE_TYPE_SYSTEM_AUDIT:
			case SEC_ACE_TYPE_SYSTEM_ALARM:
			case SEC_ACE_TYPE_ALLOWED_COMPOUND:
				break;

			case SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT:
			case SEC_ACE_TYPE_ACCESS_DENIED_OBJECT:
			case SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT:
			case SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT:
				if (ace->object.object.flags & SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT) {
					inherited_object = ace->object.object.inherited_type.inherited_type;
				}

				if (!object_in_list(object_list, &inherited_object)) {
					tmp_acl->aces[tmp_acl->num_aces].flags |= SEC_ACE_FLAG_INHERIT_ONLY;
				}

				break;
			}

			tmp_acl->num_aces++;
			if (is_container) {
				if (!(ace->flags & SEC_ACE_FLAG_NO_PROPAGATE_INHERIT) &&
				    (desc_ace_has_generic(ace))) {
					    tmp_acl->aces = talloc_realloc(tmp_acl,
									   tmp_acl->aces,
									   struct security_ace,
									   tmp_acl->num_aces+1);
					    if (tmp_acl->aces == NULL) {
						    talloc_free(tmp_ctx);
						    return NULL;
					    }
					    tmp_acl->aces[tmp_acl->num_aces] = *ace;
					    security_ace_expand_generic_rights(&tmp_acl->aces[tmp_acl->num_aces],
								owner,
								group);
					    tmp_acl->aces[tmp_acl->num_aces].flags = SEC_ACE_FLAG_INHERITED_ACE;
					    tmp_acl->num_aces++;
				}
			}
		}
	}
	if (tmp_acl->num_aces == 0) {
		return NULL;
	}
	if (acl) {
		tmp_acl->revision = acl->revision;
	}
	return tmp_acl;
}

static struct security_acl *process_user_acl(TALLOC_CTX *mem_ctx,
					     struct security_acl *acl,
					     bool is_container,
					     struct dom_sid *owner,
					     struct dom_sid *group,
					     struct GUID *object_list,
					     bool is_protected)
{
	uint32_t i;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct security_acl *tmp_acl = talloc_zero(tmp_ctx, struct security_acl);
	struct security_acl *new_acl;

	if (!acl)
		return NULL;

	if (!tmp_acl)
		return NULL;

	tmp_acl->revision = acl->revision;
	DEBUG(6,(__location__ ": acl revision %d\n", acl->revision));

	for (i=0; i < acl->num_aces; i++){
		struct security_ace *ace = &acl->aces[i];
		/* Remove ID flags from user-provided ACEs
		 * if we break inheritance, ignore them otherwise */
		if (ace->flags & SEC_ACE_FLAG_INHERITED_ACE) {
			if (is_protected) {
				ace->flags &= ~SEC_ACE_FLAG_INHERITED_ACE;
			} else {
				continue;
			}
		}

		if (ace->flags & SEC_ACE_FLAG_INHERIT_ONLY &&
		    !(ace->flags & SEC_ACE_FLAG_CONTAINER_INHERIT ||
		      ace->flags & SEC_ACE_FLAG_OBJECT_INHERIT))
			continue;

		tmp_acl->aces = talloc_realloc(tmp_acl,
					       tmp_acl->aces,
					       struct security_ace,
					       tmp_acl->num_aces+1);
		tmp_acl->aces[tmp_acl->num_aces] = *ace;
		tmp_acl->num_aces++;
		if (ace->flags & SEC_ACE_FLAG_INHERIT_ONLY) {
			continue;
		}
		/* if the ACE contains CO, CG, GA, GE, GR or GW, and is inheritable
		 * it has to be expanded to two aces, the original as IO,
		 * and another one where these are translated */
		if (desc_ace_has_generic(ace)) {
			if (!(ace->flags & SEC_ACE_FLAG_CONTAINER_INHERIT)) {
				security_ace_expand_generic_rights(&tmp_acl->aces[tmp_acl->num_aces-1],
						    owner,
						    group);
			} else {
				/*The original ACE becomes read only */
				tmp_acl->aces[tmp_acl->num_aces-1].flags |= SEC_ACE_FLAG_INHERIT_ONLY;
				tmp_acl->aces = talloc_realloc(tmp_acl, tmp_acl->aces,
							       struct security_ace,
							       tmp_acl->num_aces+1);
				/* add a new ACE with expanded generic info */
				tmp_acl->aces[tmp_acl->num_aces] = *ace;
				security_ace_expand_generic_rights(&tmp_acl->aces[tmp_acl->num_aces],
						    owner,
						    group);
				tmp_acl->num_aces++;
			}
		}
	}
	new_acl = security_acl_dup(mem_ctx,tmp_acl);

	if (new_acl)
		new_acl->revision = acl->revision;

	talloc_free(tmp_ctx);
	return new_acl;
}

static void security_descriptor_log(struct security_descriptor *sd,
				    const char *message,
				    int level)
{
	if (sd) {
		DEBUG(level,("%s: %s\n", message,
			     ndr_print_struct_string(0,(ndr_print_fn_t)ndr_print_security_descriptor,
						     "", sd)));
	}
	else {
		DEBUG(level,("%s: NULL\n", message));
	}
}

#if 0
static void cr_descr_log_acl(struct security_acl *acl,
				    const char *message,
				    int level)
{
	if (acl) {
		DEBUG(level,("%s: %s\n", message,
			     ndr_print_struct_string(0,(ndr_print_fn_t)ndr_print_security_acl,
						     "", acl)));
	}
	else {
		DEBUG(level,("%s: NULL\n", message));
	}
}
#endif

static bool compute_acl(struct security_descriptor *parent_sd,
			struct security_descriptor *creator_sd,
			bool is_container,
			uint32_t inherit_flags,
			struct GUID *object_list,
			uint32_t (*generic_map)(uint32_t access_mask),
			struct security_token *token,
			struct security_descriptor *new_sd) /* INOUT argument */
{
	struct security_acl *user_dacl, *user_sacl, *inherited_dacl, *inherited_sacl;
	int level = 10;

	if (!parent_sd || !(inherit_flags & SEC_DACL_AUTO_INHERIT)) {
		inherited_dacl = NULL;
	} else if (creator_sd && (creator_sd->type & SEC_DESC_DACL_PROTECTED)) {
		inherited_dacl = NULL;
	} else {
		inherited_dacl = calculate_inherited_from_parent(new_sd,
								 parent_sd->dacl,
								 is_container,
								 new_sd->owner_sid,
								 new_sd->group_sid,
								 object_list);
	}


	if (!parent_sd || !(inherit_flags & SEC_SACL_AUTO_INHERIT)) {
		inherited_sacl = NULL;
	} else if (creator_sd && (creator_sd->type & SEC_DESC_SACL_PROTECTED)) {
		inherited_sacl = NULL;
	} else {
		inherited_sacl = calculate_inherited_from_parent(new_sd,
								 parent_sd->sacl,
								 is_container,
								 new_sd->owner_sid,
								 new_sd->group_sid,
								 object_list);
	}

	if (!creator_sd || (inherit_flags & SEC_DEFAULT_DESCRIPTOR)) {
		user_dacl = NULL;
		user_sacl = NULL;
	} else {
		user_dacl = process_user_acl(new_sd,
					     creator_sd->dacl,
					     is_container,
					     new_sd->owner_sid,
					     new_sd->group_sid,
					     object_list,
					     creator_sd->type & SEC_DESC_DACL_PROTECTED);
		user_sacl = process_user_acl(new_sd,
					     creator_sd->sacl,
					     is_container,
					     new_sd->owner_sid,
					     new_sd->group_sid,
					     object_list,
					     creator_sd->type & SEC_DESC_SACL_PROTECTED);
	}
	security_descriptor_log(parent_sd, __location__"parent_sd", level);
	security_descriptor_log(creator_sd,__location__ "creator_sd", level);

	new_sd->dacl = security_acl_concatenate(new_sd, user_dacl, inherited_dacl);
	if (new_sd->dacl) {
		new_sd->type |= SEC_DESC_DACL_PRESENT;
	}
	if (inherited_dacl) {
		new_sd->type |= SEC_DESC_DACL_AUTO_INHERITED;
	}

	new_sd->sacl = security_acl_concatenate(new_sd, user_sacl, inherited_sacl);
	if (new_sd->sacl) {
		new_sd->type |= SEC_DESC_SACL_PRESENT;
	}
	if (inherited_sacl) {
		new_sd->type |= SEC_DESC_SACL_AUTO_INHERITED;
	}
	/* This is a hack to handle the fact that
	 * apprantly any AI flag provided by the user is preserved */
	if (creator_sd)
		new_sd->type |= creator_sd->type;
	security_descriptor_log(new_sd, __location__"final sd", level);
	return true;
}

struct security_descriptor *
security_descriptor_create(TALLOC_CTX *mem_ctx,
						       struct security_descriptor *parent_sd,
						       struct security_descriptor *creator_sd,
						       bool is_container,
						       struct GUID *object_list,
						       uint32_t inherit_flags,
						       struct security_token *token,
						       struct dom_sid *default_owner, /* valid only for DS, NULL for the other RSs */
						       struct dom_sid *default_group, /* valid only for DS, NULL for the other RSs */
						       uint32_t (*generic_map)(uint32_t access_mask))
{
	struct security_descriptor *new_sd;
	struct dom_sid *new_owner = NULL;
	struct dom_sid *new_group = NULL;

	new_sd = security_descriptor_initialise(mem_ctx);
	if (!new_sd) {
		return NULL;
	}

	if (!creator_sd || !creator_sd->owner_sid) {
		if ((inherit_flags & SEC_OWNER_FROM_PARENT) && parent_sd) {
			new_owner = parent_sd->owner_sid;
		} else if (!default_owner) {
			new_owner = &token->sids[PRIMARY_USER_SID_INDEX];
		} else {
			new_owner = default_owner;
			new_sd->type |= SEC_DESC_OWNER_DEFAULTED;
		}
	} else {
		new_owner = creator_sd->owner_sid;
	}

	if (!creator_sd || !creator_sd->group_sid){
		if ((inherit_flags & SEC_GROUP_FROM_PARENT) && parent_sd) {
			new_group = parent_sd->group_sid;
		} else if (!default_group && token->num_sids > PRIMARY_GROUP_SID_INDEX) {
			new_group = &token->sids[PRIMARY_GROUP_SID_INDEX];
		} else if (!default_group) {
			/* This will happen only for anonymous, which has no other groups */
			new_group = &token->sids[PRIMARY_USER_SID_INDEX];
		} else {
			new_group = default_group;
			new_sd->type |= SEC_DESC_GROUP_DEFAULTED;
		}
	} else {
		new_group = creator_sd->group_sid;
	}

	new_sd->owner_sid = talloc_memdup(new_sd, new_owner, sizeof(struct dom_sid));
	new_sd->group_sid = talloc_memdup(new_sd, new_group, sizeof(struct dom_sid));
	if (!new_sd->owner_sid || !new_sd->group_sid){
		talloc_free(new_sd);
		return NULL;
	}

	if (!compute_acl(parent_sd, creator_sd,
			 is_container, inherit_flags, object_list,
			 generic_map,token,new_sd)){
		talloc_free(new_sd);
		return NULL;
	}

	return new_sd;
}

static struct dom_sid *
security_descriptor_ds_get_default_admin_group(TALLOC_CTX *mem_ctx,
					       SD_PARTITION partition,
					       const struct security_token *token,
					       const struct dom_sid *domain_sid)
{
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	struct dom_sid *da_sid = dom_sid_add_rid(tmp_ctx, domain_sid, DOMAIN_RID_ADMINS);
	struct dom_sid *ea_sid = dom_sid_add_rid(tmp_ctx, domain_sid, DOMAIN_RID_ENTERPRISE_ADMINS);
	struct dom_sid *sa_sid = dom_sid_add_rid(tmp_ctx, domain_sid, DOMAIN_RID_SCHEMA_ADMINS);
	struct dom_sid *dag_sid;

	if (token == NULL) {
		return NULL;
	}

	switch (partition) {
	case SD_PARTITION_SCHEMA:
		if (security_token_has_sid(token, sa_sid)) {
			dag_sid = dom_sid_dup(mem_ctx, sa_sid);
		} else if (security_token_has_sid(token, ea_sid)) {
			dag_sid = dom_sid_dup(mem_ctx, ea_sid);
		} else if (security_token_has_sid(token, da_sid)) {
			dag_sid = dom_sid_dup(mem_ctx, da_sid);
		} else if (security_token_is_system(token)) {
			dag_sid = dom_sid_dup(mem_ctx, sa_sid);
		} else {
			dag_sid = NULL;
		}
		break;
	case SD_PARTITION_CONFIG:
		if (security_token_has_sid(token, ea_sid)) {
			dag_sid = dom_sid_dup(mem_ctx, ea_sid);
		} else if (security_token_has_sid(token, da_sid)) {
			dag_sid = dom_sid_dup(mem_ctx, da_sid);
		} else if (security_token_is_system(token)) {
			dag_sid = dom_sid_dup(mem_ctx, ea_sid);
		} else {
			dag_sid = NULL;
		}
		break;
	case SD_PARTITION_DEFAULT:
		if (security_token_has_sid(token, da_sid)) {
			dag_sid = dom_sid_dup(mem_ctx, da_sid);
		} else if (security_token_has_sid(token, ea_sid)) {
				dag_sid = dom_sid_dup(mem_ctx, ea_sid);
		} else if (security_token_is_system(token)) {
			dag_sid = dom_sid_dup(mem_ctx, da_sid);
		} else {
			dag_sid = NULL;
		}
		break;

	case SD_PARTITION_OTHER:
	case SD_PARTITION_INVALID:
	default:
		dag_sid = NULL;
	}
	talloc_free(tmp_ctx);
	return dag_sid;
}

struct security_descriptor *
security_descriptor_ds_adjust_for_sdflags(TALLOC_CTX *mem_ctx,
					  struct security_descriptor *new_sd,
					  struct security_descriptor *old_sd,
					  uint32_t sd_flags)
{
	struct security_descriptor *final_sd;
	/* if there is no control or control == 0 modify everything */
	if (!sd_flags) {
		return new_sd;
	}

	final_sd = talloc_zero(mem_ctx, struct security_descriptor);
	final_sd->revision = SECURITY_DESCRIPTOR_REVISION_1;
	final_sd->type = SEC_DESC_SELF_RELATIVE;

	if (sd_flags & (SECINFO_OWNER)) {
		if (new_sd->owner_sid) {
			final_sd->owner_sid = talloc_memdup(mem_ctx, new_sd->owner_sid, sizeof(struct dom_sid));
		}
		final_sd->type |= new_sd->type & SEC_DESC_OWNER_DEFAULTED;
	}
	else if (old_sd) {
		if (old_sd->owner_sid) {
			final_sd->owner_sid = talloc_memdup(mem_ctx, old_sd->owner_sid, sizeof(struct dom_sid));
		}
		final_sd->type |= old_sd->type & SEC_DESC_OWNER_DEFAULTED;
	}

	if (sd_flags & (SECINFO_GROUP)) {
		if (new_sd->group_sid) {
			final_sd->group_sid = talloc_memdup(mem_ctx, new_sd->group_sid, sizeof(struct dom_sid));
		}
		final_sd->type |= new_sd->type & SEC_DESC_GROUP_DEFAULTED;
	}
	else if (old_sd) {
		if (old_sd->group_sid) {
			final_sd->group_sid = talloc_memdup(mem_ctx, old_sd->group_sid, sizeof(struct dom_sid));
		}
		final_sd->type |= old_sd->type & SEC_DESC_GROUP_DEFAULTED;
	}

	if (sd_flags & (SECINFO_SACL)) {
		final_sd->sacl = security_acl_dup(mem_ctx,new_sd->sacl);
		final_sd->type |= new_sd->type & (SEC_DESC_SACL_PRESENT |
			SEC_DESC_SACL_DEFAULTED|SEC_DESC_SACL_AUTO_INHERIT_REQ |
			SEC_DESC_SACL_AUTO_INHERITED|SEC_DESC_SACL_PROTECTED |
			SEC_DESC_SERVER_SECURITY);
	}
	else if (old_sd && old_sd->sacl) {
		final_sd->sacl = security_acl_dup(mem_ctx,old_sd->sacl);
		final_sd->type |= old_sd->type & (SEC_DESC_SACL_PRESENT |
			SEC_DESC_SACL_DEFAULTED|SEC_DESC_SACL_AUTO_INHERIT_REQ |
			SEC_DESC_SACL_AUTO_INHERITED|SEC_DESC_SACL_PROTECTED |
			SEC_DESC_SERVER_SECURITY);
	}

	if (sd_flags & (SECINFO_DACL)) {
		final_sd->dacl = security_acl_dup(mem_ctx,new_sd->dacl);
		final_sd->type |= new_sd->type & (SEC_DESC_DACL_PRESENT |
			SEC_DESC_DACL_DEFAULTED|SEC_DESC_DACL_AUTO_INHERIT_REQ |
			SEC_DESC_DACL_AUTO_INHERITED|SEC_DESC_DACL_PROTECTED |
			SEC_DESC_DACL_TRUSTED);
	}
	else if (old_sd && old_sd->dacl) {
		final_sd->dacl = security_acl_dup(mem_ctx,old_sd->dacl);
		final_sd->type |= old_sd->type & (SEC_DESC_DACL_PRESENT |
			SEC_DESC_DACL_DEFAULTED|SEC_DESC_DACL_AUTO_INHERIT_REQ |
			SEC_DESC_DACL_AUTO_INHERITED|SEC_DESC_DACL_PROTECTED |
			SEC_DESC_DACL_TRUSTED);
	}
	/* not so sure about this */
	final_sd->type |= new_sd->type & SEC_DESC_RM_CONTROL_VALID;
	return final_sd;
}

static struct dom_sid *security_descriptor_get_default_group(TALLOC_CTX *mem_ctx,
						  struct dom_sid *dag)
{
	/*
	 * This depends on the function level of the DC
	 * which is 2008R2 in our case. Which means it is
	 * higher than 2003 and we should use the
	 * "default administrator group" also as owning group.
	 *
	 * This matches dcpromo for a 2003 domain
	 * on a Windows 2008R2 DC.
	 */
	return dag;
}

DATA_BLOB *security_descriptor_ds_get_sd_to_display(TALLOC_CTX *mem_ctx,
						    const DATA_BLOB *sd,
						    uint32_t sd_flags)
{
	struct security_descriptor *final_sd;
	DATA_BLOB *linear_sd;
	enum ndr_err_code ndr_err;
	struct security_descriptor *old_sd;

	old_sd = talloc(mem_ctx, struct security_descriptor);
	if (!old_sd) {
		return NULL;
	}
	ndr_err = ndr_pull_struct_blob(sd, old_sd,
				       old_sd,
				       (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(old_sd);
		return NULL;
	}

	final_sd = security_descriptor_ds_adjust_for_sdflags(mem_ctx, old_sd, NULL, sd_flags);

	if (!final_sd) {
		return NULL;
	}

	linear_sd = talloc(mem_ctx, DATA_BLOB);
	if (!linear_sd) {
		return NULL;
	}

	ndr_err = ndr_push_struct_blob(linear_sd, mem_ctx,
				       final_sd,
				       (ndr_push_flags_fn_t)ndr_push_security_descriptor);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		return NULL;
	}

	return linear_sd;
}




struct security_descriptor *security_descriptor_ds_create_as_sd(TALLOC_CTX *mem_ctx,
								const struct security_token *token,
								const struct dom_sid *domain_sid,
								const char *defaultSecurityDescriptor,
								const struct GUID *schemaIDGUID,
								const DATA_BLOB *parent,
								const DATA_BLOB *object,
								const DATA_BLOB *old_sd,
								SD_PARTITION partition,
								uint32_t sd_flags)
{
	struct security_descriptor *user_descriptor = NULL, *parent_descriptor = NULL;
	struct security_descriptor *old_descriptor = NULL;
	struct security_descriptor *new_sd, *final_sd;
	enum ndr_err_code ndr_err;
	struct dom_sid *default_owner;
	struct dom_sid *default_group;
	struct security_descriptor *default_descriptor = NULL;
	struct GUID *object_list = NULL;

	if (defaultSecurityDescriptor != NULL) {
		if (domain_sid != NULL) {
			default_descriptor = sddl_decode(mem_ctx,
							 defaultSecurityDescriptor,
							 domain_sid);
		}
		object_list = talloc_zero_array(mem_ctx, struct GUID, 2);
		if (object_list == NULL) {
			return NULL;
		}
		if (schemaIDGUID != NULL) {
			object_list[0] = *schemaIDGUID;
		}
	}

	if (object) {
		user_descriptor = talloc(mem_ctx, struct security_descriptor);
		if (!user_descriptor) {
			return NULL;
		}
		ndr_err = ndr_pull_struct_blob(object, user_descriptor,
					       user_descriptor,
					       (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(user_descriptor);
			return NULL;
		}
	} else {
		user_descriptor = default_descriptor;
	}

	if (old_sd) {
		old_descriptor = talloc(mem_ctx, struct security_descriptor);
		if (!old_descriptor) {
			return NULL;
		}
		ndr_err = ndr_pull_struct_blob(old_sd, old_descriptor,
					       old_descriptor,
					       (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(old_descriptor);
			return NULL;
		}
	}

	if (parent) {
		parent_descriptor = talloc(mem_ctx, struct security_descriptor);
		if (!parent_descriptor) {
			return NULL;
		}
		ndr_err = ndr_pull_struct_blob(parent, parent_descriptor,
					       parent_descriptor,
					       (ndr_pull_flags_fn_t)ndr_pull_security_descriptor);

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(parent_descriptor);
			return NULL;
		}
	}

	if (user_descriptor && default_descriptor &&
	    (user_descriptor->dacl == NULL))
	{
		user_descriptor->dacl = default_descriptor->dacl;
		user_descriptor->type |= default_descriptor->type & (
			SEC_DESC_DACL_PRESENT |
			SEC_DESC_DACL_DEFAULTED|SEC_DESC_DACL_AUTO_INHERIT_REQ |
			SEC_DESC_DACL_AUTO_INHERITED|SEC_DESC_DACL_PROTECTED |
			SEC_DESC_DACL_TRUSTED);
	}

	if (user_descriptor && default_descriptor &&
	    (user_descriptor->sacl == NULL))
	{
		user_descriptor->sacl = default_descriptor->sacl;
		user_descriptor->type |= default_descriptor->type & (
			SEC_DESC_SACL_PRESENT |
			SEC_DESC_SACL_DEFAULTED|SEC_DESC_SACL_AUTO_INHERIT_REQ |
			SEC_DESC_SACL_AUTO_INHERITED|SEC_DESC_SACL_PROTECTED |
			SEC_DESC_SERVER_SECURITY);
	}


	if (!(sd_flags & SECINFO_OWNER) && user_descriptor) {
		user_descriptor->owner_sid = NULL;

		/*
		 * We need the correct owner sid
		 * when calculating the DACL or SACL
		 */
		if (old_descriptor) {
			user_descriptor->owner_sid = old_descriptor->owner_sid;
		}
	}
	if (!(sd_flags & SECINFO_GROUP) && user_descriptor) {
		user_descriptor->group_sid = NULL;

		/*
		 * We need the correct group sid
		 * when calculating the DACL or SACL
		 */
		if (old_descriptor) {
			user_descriptor->group_sid = old_descriptor->group_sid;
		}
	}
	if (!(sd_flags & SECINFO_DACL) && user_descriptor) {
		user_descriptor->dacl = NULL;

		/*
		 * We add SEC_DESC_DACL_PROTECTED so that
		 * create_security_descriptor() skips
		 * the unused inheritance calculation
		 */
		user_descriptor->type |= SEC_DESC_DACL_PROTECTED;
	}
	if (!(sd_flags & SECINFO_SACL) && user_descriptor) {
		user_descriptor->sacl = NULL;

		/*
		 * We add SEC_DESC_SACL_PROTECTED so that
		 * create_security_descriptor() skips
		 * the unused inheritance calculation
		 */
		user_descriptor->type |= SEC_DESC_SACL_PROTECTED;
	}

	default_owner = security_descriptor_ds_get_default_admin_group(mem_ctx, partition,
								       token, domain_sid);
	default_group = security_descriptor_get_default_group(mem_ctx, default_owner);
	new_sd = security_descriptor_create(mem_ctx,
					    parent_descriptor,
					    user_descriptor,
					    true,
					    object_list,
					    SEC_DACL_AUTO_INHERIT |
					    SEC_SACL_AUTO_INHERIT,
					    token,
					    default_owner, default_group,
					    security_descriptor_ds_map_generic_rights);
	if (!new_sd) {
		return NULL;
	}
	final_sd = security_descriptor_ds_adjust_for_sdflags(mem_ctx, new_sd, old_descriptor, sd_flags);

	if (!final_sd) {
		return NULL;
	}

	if (final_sd->dacl) {
		final_sd->dacl->revision = SECURITY_ACL_REVISION_ADS;
	}
	if (final_sd->sacl) {
		final_sd->sacl->revision = SECURITY_ACL_REVISION_ADS;
	}

	return final_sd;
}

/* TODO mem_ctx must always be deleted after use, the function does not free on error */
DATA_BLOB *security_descriptor_ds_create_as_blob(TALLOC_CTX *mem_ctx,
						 const DATA_BLOB *blob_token,
						 const DATA_BLOB *blob_domain_sid,
						 const char *defaultSecurityDescriptor,
						 const DATA_BLOB *blob_schemaIDGUID,
						 const DATA_BLOB *parent,
						 const DATA_BLOB *object,
						 const DATA_BLOB *old_sd,
						 SD_PARTITION partition,
						 uint32_t sd_flags,
						 char **out_as_sddl)
{
	DATA_BLOB *linear_sd;
	struct security_descriptor *final_sd = NULL;
	enum ndr_err_code ndr_err;
	struct security_token *token;
	struct dom_sid *domain_sid;
	struct GUID *schemaIDGUID = NULL;

	if (blob_token) {
		token = talloc(mem_ctx, struct security_token);
		if (!token) {
			return NULL;
		}
		ndr_err = ndr_pull_struct_blob(blob_token, token,
					       token,
					       (ndr_pull_flags_fn_t)ndr_pull_security_token);

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(token);
			token = NULL;
		}
	}

	if (blob_domain_sid) {
		domain_sid = talloc(mem_ctx, struct dom_sid);
		if (!domain_sid) {
			return NULL;
		}
               ndr_err = ndr_pull_struct_blob(blob_domain_sid, mem_ctx,
                                              domain_sid,
                                              (ndr_pull_flags_fn_t)ndr_pull_dom_sid);

               if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
                       talloc_free(domain_sid);
                       domain_sid = NULL;
	       }
	}

	if (blob_schemaIDGUID) {
		schemaIDGUID = talloc(mem_ctx, struct GUID);
		ndr_err = ndr_pull_struct_blob(blob_schemaIDGUID, schemaIDGUID,
					       schemaIDGUID,
					       (ndr_pull_flags_fn_t)ndr_pull_GUID);

		if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
			talloc_free(schemaIDGUID);
			return NULL;
		}
	}

	final_sd = security_descriptor_ds_create_as_sd(mem_ctx,
						       token,
						       domain_sid,
						       defaultSecurityDescriptor,
						       schemaIDGUID,
						       parent,
						       object,
						       old_sd,
						       partition,
						       sd_flags);

	linear_sd = talloc(mem_ctx, DATA_BLOB);
	if (!linear_sd) {
		return NULL;
	}

	ndr_err = ndr_push_struct_blob(linear_sd, mem_ctx,
				       final_sd,
				       (ndr_push_flags_fn_t)ndr_push_security_descriptor);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		talloc_free(linear_sd);
		return NULL;
	}
	if (linear_sd != NULL && final_sd != NULL) {
		*out_as_sddl = sddl_encode(mem_ctx, final_sd, domain_sid);
	}

	return linear_sd;

}
