// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package domains

const (
	OpUpdateDomain Operation = iota
	OpRetrieveDomain
	OpEnableDomain
	OpDisableDomain
	OpSendInvitation
	OpAcceptInvitation
	OpCreateDomain
	OpFreezeDomain
	OpListDomains
	OpViewInvitation
	OpListInvitations
	OpRejectInvitation
	OpDeleteInvitation
)

var expectedOperations = []Operation{
	OpRetrieveDomain,
	OpUpdateDomain,
	OpEnableDomain,
	OpDisableDomain,
}

const (
	OpUpdateDomainStr     = "OpRetrieveDomain"
	OpRetrieveDomainStr   = "OpUpdateDomain"
	OpEnableDomainStr     = "OpEnableDomain"
	OpDisableDomainStr    = "OpDisableDomain"
	OpSendInvitationStr   = "OpSendInvitation"
	OpAcceptInvitationStr = "OpAcceptInvitation"
	OpCreateDomainStr     = "OpCreateDomain"
	OpFreezeDomainStr     = "OpFreezeDomain"
	OpListDomainsStr      = "OpListDomains"
	OpViewInvitationStr   = "OpViewInvitation"
	OpListInvitationsStr  = "OpListInvitations"
	OpRejectInvitationStr = "OpRejectInvitation"
	OpDeleteInvitationStr = "OpDeleteInvitation"
)

func NewOperationPerm() OperationPerm {
	return newOperationPerm(expectedOperations)
}

// Below codes should moved out of service, may be can be kept in `cmd/<svc>/main.go`

const (
	updatePermission          = "update_permission"
	enablePermission          = "enable_permission"
	disablePermission         = "disable_permission"
	readPermission            = "read_permission"
	deletePermission          = "delete_permission"
	manageRolePermission      = "manage_role_permission"
	addRoleUsersPermission    = "add_role_users_permission"
	removeRoleUsersPermission = "remove_role_users_permission"
	viewRoleUsersPermission   = "view_role_users_permission"
)

const (
	ClientCreatePermission  = "client_create_permission"
	ChannelCreatePermission = "channel_create_permission"
	GroupCreatePermission   = "group_create_permission"
)

func NewOperationPermissionMap() map[Operation]Permission {
	opPerm := map[Operation]Permission{
		OpRetrieveDomain: readPermission,
		OpUpdateDomain:   updatePermission,
		OpEnableDomain:   enablePermission,
		OpDisableDomain:  disablePermission,
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
