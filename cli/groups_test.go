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
	childrenCommand = "children"
	parentsCommand  = "parents"
	usersCommand    = "users"
	assignCommand   = "assign"
	unassignCommand = "unassign"
)

var group = mgsdk.Group{
	ID:   testsutil.GenerateUUID(&testing.T{}),
	Name: "testgroup",
}

func TestCreateGroupCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	groupJson := "{\"name\":\"testgroup\", \"metadata\":{\"key1\":\"value1\"}}"
	groupCmd := cli.NewGroupsCmd()
	rootCmd := setFlags(groupCmd)

	gp := mgsdk.Group{}
	cases := []struct {
		desc          string
		args          []string
		logType       outputLog
		group         mgsdk.Group
		sdkErr        errors.SDKError
		errLogMessage string
	}{
		{
			desc: "create group successfully",
			args: []string{
				createCommand,
				groupJson,
				token,
			},
			group:   group,
			logType: entityLog,
		},
		{
			desc: "create group with invalid args",
			args: []string{
				createCommand,
				groupJson,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "create group with invalid json",
			args: []string{
				createCommand,
				"{\"name\":\"testgroup\", \"metadata\":{\"key1\":\"value1\"}",
				token,
			},
			sdkErr:        errors.NewSDKError(errors.New("unexpected end of JSON input")),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.New("unexpected end of JSON input")),
			logType:       errLog,
		},
		{
			desc: "create group with invalid token",
			args: []string{
				createCommand,
				groupJson,
				invalidToken,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusUnauthorized),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusUnauthorized)),
			logType:       errLog,
		},
		{
			desc: "create group without domain token",
			args: []string{
				createCommand,
				groupJson,
				tokenWithoutDomain,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrDomainAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrDomainAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		sdkCall := sdkMock.On("CreateGroup", mock.Anything, tc.args[2]).Return(tc.group, tc.sdkErr)
		out := executeCommand(t, rootCmd, tc.args...)

		switch tc.logType {
		case entityLog:
			err := json.Unmarshal([]byte(out), &gp)
			assert.Nil(t, err)
			assert.Equal(t, tc.group, gp, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.group, gp))
		case usageLog:
			assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
		case errLog:
			assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
		}
		sdkCall.Unset()
	}
}

func TestGetGroupsCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	groupCmd := cli.NewGroupsCmd()
	rootCmd := setFlags(groupCmd)

	var ch mgsdk.Group
	var page mgsdk.GroupsPage

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		page          mgsdk.GroupsPage
		group         mgsdk.Group
		logType       outputLog
		errLogMessage string
	}{
		{
			desc: "get all groups successfully",
			args: []string{
				getCommand,
				all,
				token,
			},
			page: mgsdk.GroupsPage{
				Groups: []mgsdk.Group{group},
			},
			logType: entityLog,
		},
		{
			desc: "get all groups with invalid args",
			args: []string{
				getCommand,
				all,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "get children groups successfully",
			args: []string{
				getCommand,
				childrenCommand,
				group.ID,
				token,
			},
			page: mgsdk.GroupsPage{
				Groups: []mgsdk.Group{group},
			},
			logType: entityLog,
		},
		{
			desc: "get children groups with invalid args",
			args: []string{
				getCommand,
				childrenCommand,
				group.ID,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "get children groups with invalid token",
			args: []string{
				getCommand,
				childrenCommand,
				group.ID,
				invalidToken,
			},
			logType:       errLog,
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
		},
		{
			desc: "get parents groups successfully",
			args: []string{
				getCommand,
				parentsCommand,
				group.ID,
				token,
			},
			page: mgsdk.GroupsPage{
				Groups: []mgsdk.Group{group},
			},
			logType: entityLog,
		},
		{
			desc: "get parents groups with invalid args",
			args: []string{
				getCommand,
				parentsCommand,
				group.ID,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "get parents groups with invalid token",
			args: []string{
				getCommand,
				parentsCommand,
				group.ID,
				invalidToken,
			},
			logType:       errLog,
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
		},
		{
			desc: "get group with id",
			args: []string{
				getCommand,
				group.ID,
				token,
			},
			logType: entityLog,
			group:   group,
		},
		{
			desc: "get groups with invalid args",
			args: []string{
				getCommand,
				all,
			},
			logType: usageLog,
		},
		{
			desc: "get all groups with invalid token",
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
			desc: "get group without domain token",
			args: []string{
				getCommand,
				group.ID,
				invalidToken,
			},
			logType:       errLog,
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrDomainAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrDomainAuthorization, http.StatusForbidden)),
		},
		{
			desc: "get group with invalid id",
			args: []string{
				getCommand,
				invalidID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "get group with invalid args",
			args: []string{
				getCommand,
				group.ID,
				token,
				extraArg,
			},
			logType: usageLog,
		},
	}

	for _, tc := range cases {
		sdkCall := sdkMock.On("Group", mock.Anything, mock.Anything).Return(tc.group, tc.sdkErr)
		sdkCall1 := sdkMock.On("Groups", mock.Anything, mock.Anything).Return(tc.page, tc.sdkErr)
		sdkCall2 := sdkMock.On("Parents", mock.Anything, mock.Anything, mock.Anything).Return(tc.page, tc.sdkErr)
		sdkCall3 := sdkMock.On("Children", mock.Anything, mock.Anything, mock.Anything).Return(tc.page, tc.sdkErr)

		out := executeCommand(t, rootCmd, tc.args...)

		switch tc.logType {
		case entityLog:
			if tc.args[1] == all {
				err := json.Unmarshal([]byte(out), &page)
				assert.Nil(t, err)
				assert.Equal(t, tc.page, page, fmt.Sprintf("%v unexpected response, expected: %v, got: %v", tc.desc, tc.page, page))
			} else {
				err := json.Unmarshal([]byte(out), &ch)
				assert.Nil(t, err)
				assert.Equal(t, tc.group, ch, fmt.Sprintf("%v unexpected response, expected: %v, got: %v", tc.desc, tc.group, ch))
			}
		case errLog:
			assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
		case usageLog:
			assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
		}
		sdkCall.Unset()
		sdkCall1.Unset()
		sdkCall2.Unset()
		sdkCall3.Unset()
	}
}

func TestDeletegroupCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	groupCmd := cli.NewGroupsCmd()
	rootCmd := setFlags(groupCmd)

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		logType       outputLog
		errLogMessage string
	}{
		{
			desc: "delete group successfully",
			args: []string{
				deleteCommand,
				group.ID,
				token,
			},
			logType: okLog,
		},
		{
			desc: "delete group with invalid args",
			args: []string{
				deleteCommand,
				group.ID,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "delete group with invalid id",
			args: []string{
				deleteCommand,
				invalidID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "delete group with invalid token",
			args: []string{
				deleteCommand,
				group.ID,
				invalidToken,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		sdkCall := sdkMock.On("DeleteGroup", tc.args[1], tc.args[2]).Return(tc.sdkErr)
		out := executeCommand(t, rootCmd, tc.args...)

		switch tc.logType {
		case okLog:
			assert.True(t, strings.Contains(out, "ok"), fmt.Sprintf("%s unexpected response: expected success message, got: %v", tc.desc, out))
		case errLog:
			assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
		case usageLog:
			assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
		}
		sdkCall.Unset()
	}
}

func TestUpdategroupCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	groupCmd := cli.NewGroupsCmd()
	rootCmd := setFlags(groupCmd)

	newgroupJson := fmt.Sprintf("{\"id\":\"%s\",\"name\" : \"group1\"}", group.ID)
	cases := []struct {
		desc          string
		args          []string
		group         mgsdk.Group
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
	}{
		{
			desc: "update group successfully",
			args: []string{
				updateCommand,
				newgroupJson,
				token,
			},
			group: mgsdk.Group{
				Name: "newgroup1",
				ID:   group.ID,
			},
			logType: entityLog,
		},
		{
			desc: "update group with invalid args",
			args: []string{
				updateCommand,
				newgroupJson,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "update group with invalid group id",
			args: []string{
				updateCommand,

				fmt.Sprintf("{\"id\":\"%s\",\"name\" : \"group1\"}", invalidID),
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "update group with invalid json syntax",
			args: []string{
				updateCommand,
				fmt.Sprintf("{\"id\":\"%s\",\"name\" : \"group1\"", group.ID),
				token,
			},
			sdkErr:        errors.NewSDKError(errors.New("unexpected end of JSON input")),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.New("unexpected end of JSON input")),
			logType:       errLog,
		},
	}
	for _, tc := range cases {
		var ch mgsdk.Group
		sdkCall := sdkMock.On("UpdateGroup", mock.Anything, tc.args[2]).Return(tc.group, tc.sdkErr)
		out := executeCommand(t, rootCmd, tc.args...)

		switch tc.logType {
		case entityLog:
			err := json.Unmarshal([]byte(out), &ch)
			assert.Nil(t, err)
			assert.Equal(t, tc.group, ch, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.group, ch))
		case usageLog:
			assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
		case errLog:
			assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
		}
		sdkCall.Unset()
	}
}

func TestListUsersCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	groupsCmd := cli.NewGroupsCmd()
	rootCmd := setFlags(groupsCmd)

	var up mgsdk.UsersPage
	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
		page          mgsdk.UsersPage
	}{
		{
			desc: "list users successfully",
			args: []string{
				usersCommand,
				group.ID,
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
			desc: "list users with invalid args",
			args: []string{
				usersCommand,
				group.ID,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "list users with invalid id",
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
		sdkCall := sdkMock.On("ListGroupUsers", tc.args[1], mock.Anything, tc.args[2]).Return(tc.page, tc.sdkErr)
		out := executeCommand(t, rootCmd, tc.args...)
		switch tc.logType {
		case entityLog:
			err := json.Unmarshal([]byte(out), &up)
			if err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}
			assert.Equal(t, tc.page, up, fmt.Sprintf("%v unexpected response, expected: %v, got: %v", tc.desc, tc.page, up))
		case usageLog:
			assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
		case errLog:
			assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
		}
		sdkCall.Unset()
	}
}

func TestListChannelsCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	groupsCmd := cli.NewGroupsCmd()
	rootCmd := setFlags(groupsCmd)

	var cp mgsdk.ChannelsPage
	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		logType       outputLog
		page          mgsdk.ChannelsPage
	}{
		{
			desc: "list channels successfully",
			args: []string{
				channelsCommand,
				group.ID,
				token,
			},
			page: mgsdk.ChannelsPage{
				PageRes: mgsdk.PageRes{
					Total:  1,
					Offset: 0,
					Limit:  10,
				},
				Channels: []mgsdk.Channel{channel},
			},
			logType: entityLog,
		},
		{
			desc: "list channels with invalid args",
			args: []string{
				channelsCommand,
				group.ID,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "list channels with invalid id",
			args: []string{
				channelsCommand,
				invalidID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
	}
	for _, tc := range cases {
		sdkCall := sdkMock.On("ListGroupChannels", tc.args[1], mock.Anything, tc.args[2]).Return(tc.page, tc.sdkErr)
		out := executeCommand(t, rootCmd, tc.args...)
		switch tc.logType {
		case entityLog:
			err := json.Unmarshal([]byte(out), &cp)
			if err != nil {
				t.Fatalf("Failed to unmarshal JSON: %v", err)
			}
			assert.Equal(t, tc.page, cp, fmt.Sprintf("%v unexpected response, expected: %v, got: %v", tc.desc, tc.page, cp))
		case usageLog:
			assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
		case errLog:
			assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
		}
		sdkCall.Unset()
	}
}

func TestEnablegroupCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	groupCmd := cli.NewGroupsCmd()
	rootCmd := setFlags(groupCmd)
	var ch mgsdk.Group

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		group         mgsdk.Group
		logType       outputLog
	}{
		{
			desc: "enable group successfully",
			args: []string{
				enableCommand,
				group.ID,
				validToken,
			},
			group:   group,
			logType: entityLog,
		},
		{
			desc: "delete group with invalid token",
			args: []string{
				enableCommand,
				group.ID,
				invalidToken,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "delete group with invalid group ID",
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
			desc: "enable group with invalid args",
			args: []string{
				enableCommand,
				group.ID,
				validToken,
				extraArg,
			},
			logType: usageLog,
		},
	}

	for _, tc := range cases {
		sdkCall := sdkMock.On("EnableGroup", tc.args[1], tc.args[2]).Return(tc.group, tc.sdkErr)
		out := executeCommand(t, rootCmd, tc.args...)

		switch tc.logType {
		case errLog:
			assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
		case usageLog:
			assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
		case entityLog:
			err := json.Unmarshal([]byte(out), &ch)
			assert.Nil(t, err)
			assert.Equal(t, tc.group, ch, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.group, ch))
		}

		sdkCall.Unset()
	}
}

func TestDisablegroupCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	groupsCmd := cli.NewGroupsCmd()
	rootCmd := setFlags(groupsCmd)

	var ch mgsdk.Group

	cases := []struct {
		desc          string
		args          []string
		sdkErr        errors.SDKError
		errLogMessage string
		group         mgsdk.Group
		logType       outputLog
	}{
		{
			desc: "disable group successfully",
			args: []string{
				disableCommand,
				group.ID,
				validToken,
			},
			logType: entityLog,
			group:   group,
		},
		{
			desc: "disable group with invalid token",
			args: []string{
				disableCommand,
				group.ID,
				invalidToken,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "disable group with invalid id",
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
				group.ID,
				validToken,
				extraArg,
			},
			logType: usageLog,
		},
	}

	for _, tc := range cases {
		sdkCall := sdkMock.On("DisableGroup", tc.args[1], tc.args[2]).Return(tc.group, tc.sdkErr)
		out := executeCommand(t, rootCmd, tc.args...)

		switch tc.logType {
		case errLog:
			assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
		case usageLog:
			assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
		case entityLog:
			err := json.Unmarshal([]byte(out), &ch)
			if err != nil {
				t.Fatalf("json.Unmarshal failed: %v", err)
			}
			assert.Equal(t, tc.group, ch, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.group, ch))
		}

		sdkCall.Unset()
	}
}

func TestAssignUserToGroupCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	groupsCmd := cli.NewGroupsCmd()
	rootCmd := setFlags(groupsCmd)

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
				group.ID,
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
				group.ID,
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
				group.ID,
				token,
			},
			sdkErr:        errors.NewSDKError(errors.New("unexpected end of JSON input")),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.New("unexpected end of JSON input")),
			logType:       errLog,
		},
		{
			desc: "assign user with invalid group id",
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
				group.ID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAddPolicies, http.StatusBadRequest),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAddPolicies, http.StatusBadRequest)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		sdkCall := sdkMock.On("AddUserToGroup", tc.args[4], mock.Anything, tc.args[5]).Return(tc.sdkErr)
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
	}
}

func TestUnassignUserToGroupCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	groupsCmd := cli.NewGroupsCmd()
	rootCmd := setFlags(groupsCmd)

	userIds := fmt.Sprintf("[\"%s\"]", user.ID)

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
				relation,
				userIds,
				group.ID,
				token,
			},
			logType: okLog,
		},
		{
			desc: "unassign user with invalid args",
			args: []string{
				unassignCommand,
				usersCommand,
				relation,
				userIds,
				group.ID,
				token,
				extraArg,
			},
			logType: usageLog,
		},
		{
			desc: "unassign user with invalid json",
			args: []string{
				unassignCommand,
				usersCommand,
				relation,
				fmt.Sprintf("[\"%s\"", user.ID),
				group.ID,
				token,
			},
			sdkErr:        errors.NewSDKError(errors.New("unexpected end of JSON input")),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.New("unexpected end of JSON input")),
			logType:       errLog,
		},
		{
			desc: "unassign user with invalid group id",
			args: []string{
				unassignCommand,
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
			desc: "unassign user with invalid user id",
			args: []string{
				unassignCommand,
				usersCommand,
				relation,
				fmt.Sprintf("[\"%s\"]", invalidID),
				group.ID,
				token,
			},
			sdkErr:        errors.NewSDKErrorWithStatus(svcerr.ErrAddPolicies, http.StatusBadRequest),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAddPolicies, http.StatusBadRequest)),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		sdkCall := sdkMock.On("RemoveUserFromGroup", tc.args[4], mock.Anything, tc.args[5]).Return(tc.sdkErr)
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
	}
}
