// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli_test

// CRUD and common commands
const (
	createCmd  = "create"
	updateCmd  = "update"
	getCmd     = "get"
	enableCmd  = "enable"
	disableCmd = "disable"
	freezeCmd  = "freeze"
	delCmd     = "delete"
)

// Users commands
const (
	tokCmd        = "token"
	refTokCmd     = "refreshtoken"
	profCmd       = "profile"
	resPassReqCmd = "resetpasswordrequest"
	resPassCmd    = "resetpassword"
	passCmd       = "password"
	domsCmd       = "domains"
)

// Clients commands
const (
	cliCmd     = "clients"
	connsCmd   = "connections"
	connCmd    = "connect"
	disconnCmd = "disconnect"
	shrCmd     = "share"
	unshrCmd   = "unshare"
)

// Certs commands
const (
	revokeCmd    = "revoke"
	revokeAllCmd = "revoke-all"
	issueCmd     = "issue"
)

// Messages commands
const (
	sendCmd = "send"
	readCmd = "read"
)

// Invitations commands
const (
	acceptCmd = "accept"
	rejectCmd = "reject"
)

// Role commands
const (
	rolesCmd            = "roles"
	actionsCmd          = "actions"
	availableActionsCmd = "available-actions"
	addCmd              = "add"
	listCmd             = "list"
	membersCmd          = "members"
)
