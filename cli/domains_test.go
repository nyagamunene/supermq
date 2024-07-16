// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/absmach/magistrala/cli"
	"github.com/absmach/magistrala/internal/testsutil"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	mgsdk "github.com/absmach/magistrala/pkg/sdk/go"
	sdkmocks "github.com/absmach/magistrala/pkg/sdk/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	usersCommand    = "users"
	enableCommand   = "enable"
	disableCommand  = "disable"
	assignCommand   = "assign"
	unassignCommand = "unassign"
)

var domain = mgsdk.Domain{
	ID:    testsutil.GenerateUUID(&testing.T{}),
	Name:  "testdomain",
	Alias: "alias",
}

func TestCreateDomainsCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	domainCmd := cli.NewDomainsCmd()
	rootCmd := setFlags(domainCmd)

	var dom mgsdk.Domain

	cases := []struct {
		desc          string
		args          []string
		domain        mgsdk.Domain
		errLogMessage string
		sdkErr        errors.SDKError
		logType       outputLog
	}{
		{
			desc: "create domain successfully",
			args: []string{
				createCommand,
				dom.Name,
				dom.Alias,
				validToken,
			},
			logType: entityLog,
			domain:  domain,
		},
		{
			desc: "create domain with invalid args",
			args: []string{
				createCommand,
				dom.Name,
				dom.Alias,
				validToken,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "create domain with invalid token",
			args: []string{
				createCommand,
				dom.Name,
				dom.Alias,
				invalidToken,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusUnauthorized),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusUnauthorized)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("CreateDomain", mock.Anything, mock.Anything).Return(tc.domain, tc.sdkErr)
			out := executeCommand(t, rootCmd, tc.args...)

			switch tc.logType {
			case entityLog:
				err := json.Unmarshal([]byte(out), &dom)
				assert.Nil(t, err)
				assert.Equal(t, tc.domain, dom, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.domain, dom))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			}
			sdkCall.Unset()
		})
	}
}

func TestGetDomainsCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	all := "all"
	domainCmd := cli.NewDomainsCmd()
	rootCmd := setFlags(domainCmd)

	var dom mgsdk.Domain
	var page mgsdk.DomainsPage

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		page          mgsdk.DomainsPage
		domain        mgsdk.Domain
		logType       outputLog
		errLogMessage string
	}{
		{
			desc: "get all domains successfully",
			args: []string{
				getCommand,
				all,
				validToken,
			},
			page: mgsdk.DomainsPage{
				Domains: []mgsdk.Domain{domain},
			},
			logType: entityLog,
		},
		{
			desc: "get domain with id",
			args: []string{
				getCommand,
				domain.ID,
				validToken,
			},
			logType: entityLog,
			domain:  domain,
		},
		{
			desc: "get domains with invalid args",
			args: []string{
				getCommand,
				all,
				validToken,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "get all domains with invalid token",
			args: []string{
				getCommand,
				all,
				invalidToken,
			},
			logType:       errLog,
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
		},
		{
			desc: "get domain with invalid id",
			args: []string{
				getCommand,
				invalidID,
				validToken,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("Domain", tc.args[1], tc.args[2]).Return(tc.domain, tc.sdkErr)
			sdkCall1 := sdkMock.On("Domains", mock.Anything, tc.args[2]).Return(tc.page, tc.sdkErr)

			out := executeCommand(t, rootCmd, tc.args...)

			switch tc.logType {
			case entityLog:
				if tc.args[1] == all {
					err := json.Unmarshal([]byte(out), &page)
					assert.Nil(t, err)
					assert.Equal(t, tc.page, page, fmt.Sprintf("%v unexpected response, expected: %v, got: %v", tc.desc, tc.page, page))
				} else {
					err := json.Unmarshal([]byte(out), &dom)
					assert.Nil(t, err)
					assert.Equal(t, tc.domain, dom, fmt.Sprintf("%v unexpected response, expected: %v, got: %v", tc.desc, tc.domain, dom))
				}
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			}
			sdkCall.Unset()
			sdkCall1.Unset()
		})
	}
}

func TestListDomainUsers(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	domainsCmd := cli.NewDomainsCmd()
	rootCmd := setFlags(domainsCmd)

	page := mgsdk.UsersPage{}

	cases := []struct {
		desc          string
		args          []string
		logType       outputLog
		errLogMessage string
		page          mgsdk.UsersPage
		sdkErr        errors.SDKError
	}{
		{
			desc: "get domain's users successfully",
			args: []string{
				usersCommand,
				domain.ID,
				token,
			},
			page: mgsdk.UsersPage{
				PageRes: mgsdk.PageRes{
					Total:  1,
					Offset: 0,
					Limit:  10,
				},
				Users: []mgsdk.User{user},
			},
			logType: entityLog,
		},
		{
			desc: "list domain users with invalid args",
			args: []string{
				usersCommand,
				domain.ID,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "list domain users without domain token",
			args: []string{
				usersCommand,
				domain.ID,
				tokenWithoutDomain,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrDomainAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrDomainAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "list domain users with invalid id",
			args: []string{
				usersCommand,
				invalidID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("ListDomainUsers", tc.args[1], mock.Anything, tc.args[2]).Return(tc.page, tc.sdkErr)
			out := executeCommand(t, rootCmd, tc.args...)

			switch tc.logType {
			case entityLog:
				err := json.Unmarshal([]byte(out), &page)
				if err != nil {
					t.Fatalf("Failed to unmarshal JSON: %v", err)
				}
				assert.Equal(t, tc.page, page, fmt.Sprintf("%v unexpected response, expected: %v, got: %v", tc.desc, tc.page, page))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			}
			sdkCall.Unset()
		})
	}
}

func TestUpdateDomainCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	updateCommand := "update"
	domainsCmd := cli.NewDomainsCmd()
	rootCmd := setFlags(domainsCmd)

	newDomainJson := "{\"name\" : \"domain1\"}"
	cases := []struct {
		desc          string
		args          []string
		domain        mgsdk.Domain
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
	}{
		{
			desc: "update domain successfully",
			args: []string{
				updateCommand,
				domain.ID,
				newDomainJson,
				token,
			},
			domain: mgsdk.Domain{
				Name: "newdomain1",
				ID:   domain.ID,
			},
			logType: entityLog,
		},
		{
			desc: "update domain with invalid args",
			args: []string{
				updateCommand,
				domain.ID,
				newDomainJson,
				token,
				extraArg,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "update domain with invalid id",
			args: []string{
				updateCommand,
				invalidID,
				newDomainJson,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "update domain with invalid json syntax",
			args: []string{
				updateCommand,
				domain.ID,
				"{\"name\" : \"domain1\"",
				token,
			},
			sdkErr:        errors.NewSDKError(errors.New("unexpected end of JSON input")),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.New("unexpected end of JSON input")),
			logType:       errLog,
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			var dom mgsdk.Domain
			sdkCall := sdkMock.On("UpdateDomain", mock.Anything, tc.args[3]).Return(tc.domain, tc.sdkErr)
			out := executeCommand(t, rootCmd, tc.args...)

			switch tc.logType {
			case entityLog:
				err := json.Unmarshal([]byte(out), &dom)
				assert.Nil(t, err)
				assert.Equal(t, tc.domain, dom, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.domain, dom))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			}
			sdkCall.Unset()
		})
	}
}

func TestEnableDomainCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	domainsCmd := cli.NewDomainsCmd()
	rootCmd := setFlags(domainsCmd)

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
	}{
		{
			desc: "enable domain successfully",
			args: []string{
				enableCommand,
				domain.ID,
				validToken,
			},
			logType: entityLog,
		},
		{
			desc: "delete domain with invalid token",
			args: []string{
				enableCommand,
				domain.ID,
				invalidToken,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "delete domain with invalid domain ID",
			args: []string{
				enableCommand,
				invalidID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "enable domain with invalid args",
			args: []string{
				enableCommand,
				domain.ID,
				validToken,
				extraArg,
			},
			logType: usageLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("EnableDomain", tc.args[1], tc.args[2]).Return(tc.sdkErr)
			out := executeCommand(t, rootCmd, tc.args...)

			switch tc.logType {
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case okLog:
				assert.True(t, strings.Contains(out, "ok"), fmt.Sprintf("%s unexpected response: expected success message, got: %v", tc.desc, out))
			}

			sdkCall.Unset()
		})
	}
}

func TestDisableDomainCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	domainsCmd := cli.NewDomainsCmd()
	rootCmd := setFlags(domainsCmd)

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
	}{
		{
			desc: "disable domain successfully",
			args: []string{
				disableCommand,
				domain.ID,
				validToken,
			},
			logType: okLog,
		},
		{
			desc: "disable domain with invalid token",
			args: []string{
				disableCommand,
				domain.ID,
				invalidToken,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "disable domain with invalid id",
			args: []string{
				disableCommand,
				invalidID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "disable thing with invalid args",
			args: []string{
				disableCommand,
				domain.ID,
				validToken,
				extraArg,
			},
			logType: usageLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("DisableDomain", tc.args[1], tc.args[2]).Return(tc.sdkErr)
			out := executeCommand(t, rootCmd, tc.args...)

			switch tc.logType {
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case okLog:
				assert.True(t, strings.Contains(out, "ok"), fmt.Sprintf("%s unexpected response: expected success message, got: %v", tc.desc, out))
			}

			sdkCall.Unset()
		})
	}
}

func TestAssignUserToDomainCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	domainsCmd := cli.NewDomainsCmd()
	rootCmd := setFlags(domainsCmd)

	userIds := fmt.Sprintf("[\"%s\"]", user.ID)

	cases := []struct {
		desc          string
		args          []string
		logType       outputLog
		errLogMessage string
		sdkErr        errors.SDKError
	}{
		{
			desc: "assign user successfully",
			args: []string{
				assignCommand,
				usersCommand,
				relation,
				userIds,
				domain.ID,
				token,
			},
			logType: okLog,
		},
		{
			desc: "assign user with invalid args",
			args: []string{
				assignCommand,
				usersCommand,
				relation,
				userIds,
				domain.ID,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "assign user with invalid json",
			args: []string{
				assignCommand,
				usersCommand,
				relation,
				fmt.Sprintf("[\"%s\"", user.ID),
				domain.ID,
				token,
			},
			sdkErr:        errors.NewSDKError(errors.New("unexpected end of JSON input")),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.New("unexpected end of JSON input")),
			logType:       errLog,
		},
		{
			desc: "assign user with invalid domain id",
			args: []string{
				assignCommand,
				usersCommand,
				relation,
				userIds,
				invalidID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "assign user with invalid user id",
			args: []string{
				assignCommand,
				usersCommand,
				relation,
				fmt.Sprintf("[\"%s\"]", invalidID),
				domain.ID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAddPolicies, http.StatusBadRequest),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAddPolicies, http.StatusBadRequest)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("AddUserToDomain", tc.args[4], mock.Anything, tc.args[5]).Return(tc.sdkErr)
			out := executeCommand(t, rootCmd, tc.args...)
			switch tc.logType {
			case okLog:
				assert.True(t, strings.Contains(out, "ok"), fmt.Sprintf("%s unexpected response: expected success message, got: %v", tc.desc, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			}
			sdkCall.Unset()
		})
	}
}

func TestUnassignUserTodomainCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	domainsCmd := cli.NewDomainsCmd()
	rootCmd := setFlags(domainsCmd)

	cases := []struct {
		desc          string
		args          []string
		logType       outputLog
		errLogMessage string
		sdkErr        errors.SDKError
	}{
		{
			desc: "unassign user successfully",
			args: []string{
				unassignCommand,
				usersCommand,
				user.ID,
				domain.ID,
				token,
			},
			logType: okLog,
		},
		{
			desc: "unassign user with invalid args",
			args: []string{
				unassignCommand,
				usersCommand,
				user.ID,
				domain.ID,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "unassign user with invalid domain id",
			args: []string{
				unassignCommand,
				usersCommand,
				user.ID,
				invalidID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "unassign user with invalid user id",
			args: []string{
				unassignCommand,
				usersCommand,
				invalidID,
				domain.ID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAddPolicies, http.StatusBadRequest),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAddPolicies, http.StatusBadRequest)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("RemoveUserFromDomain", tc.args[3], tc.args[2], tc.args[4]).Return(tc.sdkErr)
			out := executeCommand(t, rootCmd, tc.args...)
			switch tc.logType {
			case okLog:
				assert.True(t, strings.Contains(out, "ok"), fmt.Sprintf("%s unexpected response: expected success message, got: %v", tc.desc, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			}
			sdkCall.Unset()
		})
	}
}
