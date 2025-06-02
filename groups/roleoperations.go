// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package groups

// Internal Operations.
const (
	OpViewGroup Operation = iota
	OpUpdateGroup
	OpUpdateGroupTags
	OpEnableGroup
	OpDisableGroup
	OpRetrieveGroupHierarchy
	OpAddParentGroup
	OpRemoveParentGroup
	OpAddChildrenGroups
	OpRemoveChildrenGroups
	OpRemoveAllChildrenGroups
	OpListChildrenGroups
	OpDeleteGroup
	OpCreateGroup
	OpListGroups
	OpListUserGroups
)

var expectedOperations = []Operation{
	OpViewGroup,
	OpUpdateGroup,
	OpUpdateGroupTags,
	OpEnableGroup,
	OpDisableGroup,
	OpRetrieveGroupHierarchy,
	OpAddParentGroup,
	OpRemoveParentGroup,
	OpAddChildrenGroups,
	OpRemoveChildrenGroups,
	OpRemoveAllChildrenGroups,
	OpListChildrenGroups,
	OpDeleteGroup,
}

const (
	OpViewGroupStr               = "OpViewGroup"
	OpUpdateGroupStr             = "OpUpdateGroup"
	OpUpdateGroupTagsStr         = "OpUpdateGroupTags"
	OpEnableGroupStr             = "OpEnableGroup"
	OpDisableGroupStr            = "OpDisableGroup"
	OpRetrieveGroupHierarchyStr  = "OpRetrieveGroupHierarchy"
	OpAddParentGroupStr          = "OpAddParentGroup"
	OpRemoveParentGroupStr       = "OpRemoveParentGroup"
	OpAddChildrenGroupsStr       = "OpAddChildrenGroups"
	OpRemoveChildrenGroupsStr    = "OpRemoveChildrenGroups"
	OpRemoveAllChildrenGroupsStr = "OpRemoveAllChildrenGroups"
	OpListChildrenGroupsStr      = "OpListChildrenGroups"
	OpDeleteGroupStr             = "OpDeleteGroup"
	OpCreateGroupStr             = "OpCreateGroup"
	OpListGroupsStr              = "OpListGroups"
	OpListUserGroupsStr          = "OpListUserGroups"
)

func NewOperationPerm() OperationPerm {
	return newOperationPerm(expectedOperations)
}

// External Operations.
const (
	DomainOpCreateGroup ExternalOperation = iota
	DomainOpListGroups
	UserOpListGroups
	ClientsOpListGroups
	ChannelsOpListGroups
)

var expectedExternalOperations = []ExternalOperation{
	DomainOpCreateGroup,
	DomainOpListGroups,
	UserOpListGroups,
	ClientsOpListGroups,
	ChannelsOpListGroups,
}

const (
	DomainOpCreateGroupStr  = "DomainOpCreateGroup"
	DomainOpListGroupsStr   = "DomainOpListGroups"
	UserOpListGroupsStr     = "UserOpListGroups"
	ClientsOpListGroupsStr  = "ClientsOpListGroups"
	ChannelsOpListGroupsStr = "ChannelsOpListGroups"
)

func NewExternalOperationPerm() ExternalOperationPerm {
	return newExternalOperationPerm(expectedExternalOperations)
}

// Below codes should moved out of service, may be can be kept in `cmd/<svc>/main.go`

const (
	updatePermission    = "update_permission"
	readPermission      = "read_permission"
	deletePermission    = "delete_permission"
	setChildPermission  = "set_child_permission"
	setParentPermission = "set_parent_permission"

	manageRolePermission      = "manage_role_permission"
	addRoleUsersPermission    = "add_role_users_permission"
	removeRoleUsersPermission = "remove_role_users_permission"
	viewRoleUsersPermission   = "view_role_users_permission"
)

func NewOperationPermissionMap() map[Operation]Permission {
	opPerm := map[Operation]Permission{
		OpViewGroup:               readPermission,
		OpUpdateGroup:             updatePermission,
		OpUpdateGroupTags:         updatePermission,
		OpEnableGroup:             updatePermission,
		OpDisableGroup:            updatePermission,
		OpRetrieveGroupHierarchy:  readPermission,
		OpAddParentGroup:          setParentPermission,
		OpRemoveParentGroup:       setParentPermission,
		OpAddChildrenGroups:       setChildPermission,
		OpRemoveChildrenGroups:    setChildPermission,
		OpRemoveAllChildrenGroups: setChildPermission,
		OpListChildrenGroups:      readPermission,
		OpDeleteGroup:             deletePermission,
	}
	return opPerm
}

const (
	OpAddRole Operation = iota
	OpRemoveRole
	OpUpdateRoleName
	OpRetrieveRole
	OpRetrieveAllRoles
	OpRoleAddActions
	OpRoleListActions
	OpRoleCheckActionsExists
	OpRoleRemoveActions
	OpRoleRemoveAllActions
	OpRoleAddMembers
	OpRoleListMembers
	OpRoleCheckMembersExists
	OpRoleRemoveMembers
	OpRoleRemoveAllMembers
)

func NewRolesOperationPermissionMap() map[Operation]Permission {
	opPerm := map[Operation]Permission{
		OpAddRole:                manageRolePermission,
		OpRemoveRole:             manageRolePermission,
		OpUpdateRoleName:         manageRolePermission,
		OpRetrieveRole:           manageRolePermission,
		OpRetrieveAllRoles:       manageRolePermission,
		OpRoleAddActions:         manageRolePermission,
		OpRoleListActions:        manageRolePermission,
		OpRoleCheckActionsExists: manageRolePermission,
		OpRoleRemoveActions:      manageRolePermission,
		OpRoleRemoveAllActions:   manageRolePermission,
		OpRoleAddMembers:         addRoleUsersPermission,
		OpRoleListMembers:        viewRoleUsersPermission,
		OpRoleCheckMembersExists: viewRoleUsersPermission,
		OpRoleRemoveMembers:      removeRoleUsersPermission,
		OpRoleRemoveAllMembers:   manageRolePermission,
	}
	return opPerm
}

const (
	// External Permissions for the domain.
	domainCreateGroupPermission = "group_create_permission"
	domainListGroupPermission   = "membership"
	userListGroupsPermission    = "membership"
	clientListGroupPermission   = "read_permission"
	chanelListGroupPermission   = "read_permission"
)

func NewExternalOperationPermissionMap() map[ExternalOperation]Permission {
	extOpPerm := map[ExternalOperation]Permission{
		DomainOpCreateGroup:  domainCreateGroupPermission,
		DomainOpListGroups:   domainListGroupPermission,
		UserOpListGroups:     userListGroupsPermission,
		ClientsOpListGroups:  clientListGroupPermission,
		ChannelsOpListGroups: chanelListGroupPermission,
	}
	return extOpPerm
}
