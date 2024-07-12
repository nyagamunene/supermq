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
	mgclients "github.com/absmach/magistrala/pkg/clients"
	"github.com/absmach/magistrala/pkg/errors"
	svcerr "github.com/absmach/magistrala/pkg/errors/service"
	mgsdk "github.com/absmach/magistrala/pkg/sdk/go"
	sdk "github.com/absmach/magistrala/pkg/sdk/go"
	sdkmocks "github.com/absmach/magistrala/pkg/sdk/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	all = "all"
)

var (
	token              = "valid" + "domaintoken"
	tokenWithoutDomain = "valid"
)

var thing = mgsdk.Thing{
	ID:       testsutil.GenerateUUID(&testing.T{}),
	Name:     "testthing",
	DomainID: testsutil.GenerateUUID(&testing.T{}),
	Status:   mgclients.EnabledStatus.String(),
}

func TestCreateThingsCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	createCommand := "create"
	thingJson := "{\"name\":\"testthing\", \"metadata\":{\"key1\":\"value1\"}}"
	thingsCmd := cli.NewThingsCmd()
	rootCmd := setFlags(thingsCmd)

	var tg mgsdk.Thing

	cases := []struct {
		desc          string
		args          []string
		sdkerr        errors.SDKError
		errLogMessage string
		thing         mgsdk.Thing
		logType       outputLog
	}{
		{
			desc: "create thing successfully with token",
			args: []string{
				createCommand,
				thingJson,
				token,
			},
			thing:   thing,
			logType: entityLog,
		},
		{
			desc: "create thing without token",
			args: []string{
				createCommand,
				thingJson,
			},
			logType: usageLog,
		},
		{
			desc: "create thing with invalid token",
			args: []string{
				createCommand,
				thingJson,
				invalidToken,
			},
			sdkerr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusUnauthorized),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusUnauthorized)),
			logType:       errLog,
		},
		{
			desc: "failed to create thing",
			args: []string{
				createCommand,
				thingJson,
				token,
			},
			sdkerr:        errors.NewSDKErrorWithStatus(svcerr.ErrCreateEntity, http.StatusUnprocessableEntity),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrCreateEntity, http.StatusUnprocessableEntity)),
			logType:       errLog,
		},
		{
			desc: "create thing without domain token",
			args: []string{
				createCommand,
				thingJson,
				tokenWithoutDomain,
			},
			sdkerr:        errors.NewSDKErrorWithStatus(svcerr.ErrDomainAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrDomainAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "create thing with invalid metdata",
			args: []string{
				createCommand,
				"{\"name\":\"testthing\", \"metadata\":{\"key1\":value1}}",
				token,
			},
			sdkerr:        errors.NewSDKErrorWithStatus(errors.New("invalid character 'v' looking for beginning of value"), 306),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.New("invalid character 'v' looking for beginning of value")),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		sdkCall := sdkMock.On("CreateThing", mock.Anything, mock.Anything).Return(tc.thing, tc.sdkerr)
		out := executeCommand(t, rootCmd, tc.args...)
		switch tc.logType {
		case entityLog:
			err := json.Unmarshal([]byte(out), &tg)
			assert.Nil(t, err)
			assert.Equal(t, tc.thing, tg, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.thing, tg))
		case errLog:
			assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
		case usageLog:
			assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
		}

		sdkCall.Unset()
	}
}

func TestGetThingsCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	getCommand := "get"

	thingsCmd := cli.NewThingsCmd()
	rootCmd := setFlags(thingsCmd)

	var tg mgsdk.Thing
	var page mgsdk.ThingsPage

	cases := []struct {
		desc          string
		args          []string
		sdkerr        errors.SDKError
		errLogMessage string
		thing         mgsdk.Thing
		page          mgsdk.ThingsPage
		logType       outputLog
	}{
		{
			desc: "get things successfully",
			args: []string{
				getCommand,
				all,
				token,
			},
			logType: entityLog,
			page: mgsdk.ThingsPage{
				Things: []mgsdk.Thing{thing},
			},
		},
		{
			desc: "get things successfully with id",
			args: []string{
				getCommand,
				thing.ID,
				token,
			},
			thing: thing,
		},
		{
			desc: "get things with invalid token",
			args: []string{
				getCommand,
				all,
				invalidToken,
			},
			sdkerr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			page:          mgsdk.ThingsPage{},
			logType:       errLog,
		},
		{
			desc: "create thing without domain token",
			args: []string{
				getCommand,
				all,
				token,
			},
			sdkerr:        errors.NewSDKErrorWithStatus(svcerr.ErrDomainAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrDomainAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "get things with invalid args",
			args: []string{
				getCommand,
				all,
				invalidToken,
				all,
				invalidToken,
				all,
				invalidToken,
				all,
				invalidToken,
			},
			logType: usageLog,
		},
		{
			desc: "create thing without token",
			args: []string{
				getCommand,
				all,
			},
			logType: usageLog,
		},
	}

	for _, tc := range cases {
		sdkCall := sdkMock.On("Things", mock.Anything, mock.Anything).Return(tc.page, tc.sdkerr)
		sdkCall1 := sdkMock.On("Thing", mock.Anything, mock.Anything).Return(tc.thing, tc.sdkerr)

		out := executeCommand(t, rootCmd, tc.args...)

		if tc.logType == entityLog {
			switch {
			case tc.args[1] == all:
				err := json.Unmarshal([]byte(out), &page)
				if err != nil {
					t.Fatalf("Failed to unmarshal JSON: %v", err)
				}
			default:
				err := json.Unmarshal([]byte(out), &tg)
				if err != nil {
					t.Fatalf("Failed to unmarshal JSON: %v", err)
				}
			}
		}

		switch tc.logType {
		case errLog:
			assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
		case usageLog:
			assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
		}

		if tc.logType == entityLog {
			if tc.args[1] != all {
				assert.Equal(t, tc.thing, tg, fmt.Sprintf("%v unexpected response, expected: %v, got: %v", tc.desc, tc.thing, tg))
			} else {
				assert.Equal(t, tc.page, page, fmt.Sprintf("%v unexpected response, expected: %v, got: %v", tc.desc, tc.page, page))
			}
		}

		sdkCall.Unset()
		sdkCall1.Unset()
	}
}

func TestUpdateThingCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	updateCommand := "update"
	thingsCmd := cli.NewThingsCmd()
	rootCmd := setFlags(thingsCmd)

	tagUpdateType := "tags"
	secretUpdateType := "secret"
	newTagsJson := "[\"tag1\", \"tag2\"]"
	newTagString := []string{"tag1", "tag2"}
	newSecret := "secret"

	cases := []struct {
		desc          string
		args          []string
		sdkerr        errors.SDKError
		errLogMessage string
		thing         mgsdk.Thing
		logType       outputLog
	}{
		{
			desc: "update thing tags successfully",
			args: []string{
				updateCommand,
				tagUpdateType,
				thing.ID,
				newTagsJson,
				token,
			},
			thing: mgsdk.Thing{
				Name:     thing.Name,
				ID:       thing.ID,
				DomainID: thing.DomainID,
				Status:   thing.Status,
				Tags:     newTagString,
			},
			logType: entityLog,
		},
		{
			desc: "update thing secret successfully",
			args: []string{
				updateCommand,
				secretUpdateType,
				thing.ID,
				newSecret,
				token,
			},
			thing: mgsdk.Thing{
				Name:     thing.Name,
				ID:       thing.ID,
				DomainID: thing.DomainID,
				Status:   thing.Status,
				Credentials: sdk.Credentials{
					Secret: newSecret,
				},
			},
			logType: entityLog,
		},
		{
			desc: "p thing with invalid token",
			args: []string{
				updateCommand,
				secretUpdateType,
				thing.ID,
				newSecret,
				invalidToken,
			},
			sdkerr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "update thing with invalid args",
			args: []string{
				updateCommand,
				secretUpdateType,
				thing.ID,
				newSecret,
				token,
				extraArg,
			},
			logType: usageLog,
		},
	}

	for _, tc := range cases {
		var tg mgsdk.Thing
		sdkCall := sdkMock.On("UpdateThing", mock.Anything, mock.Anything).Return(tc.thing, tc.sdkerr)
		sdkCall1 := sdkMock.On("UpdateThingTags", mock.Anything, mock.Anything).Return(tc.thing, tc.sdkerr)
		sdkCall2 := sdkMock.On("UpdateThingSecret", mock.Anything, mock.Anything, mock.Anything).Return(tc.thing, tc.sdkerr)

		switch {
		case tc.args[1] == tagUpdateType:
			var t mgsdk.Thing
			t.Tags = []string{"tag1", "tag2"}
			t.ID = tc.args[2]

			sdkCall1 = sdkMock.On("UpdateThingTags", t, tc.args[4]).Return(tc.thing, tc.sdkerr)
		case tc.args[1] == secretUpdateType:
			var t mgsdk.Thing
			t.Credentials.Secret = tc.args[3]
			t.ID = tc.args[2]

			sdkCall2 = sdkMock.On("UpdateThingSecret", t, tc.args[3], tc.args[4]).Return(tc.thing, tc.sdkerr)
		}
		out := executeCommand(t, rootCmd, tc.args...)

		switch tc.logType {
		case entityLog:
			err := json.Unmarshal([]byte(out), &tg)
			assert.Nil(t, err)
			assert.Equal(t, tc.thing, tg, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.thing, tg))
		case errLog:
			assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
		case usageLog:
			assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
		}

		sdkCall.Unset()
		sdkCall1.Unset()
		sdkCall2.Unset()
	}
}

func TestDeleteThingCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	deleteCommand := "delete"
	thingsCmd := cli.NewThingsCmd()
	rootCmd := setFlags(thingsCmd)

	cases := []struct {
		desc          string
		args          []string
		sdkerr        errors.SDKError
		errLogMessage string
		logType       outputLog
	}{
		{
			desc: "delete thing successfully",
			args: []string{
				deleteCommand,
				thing.ID,
				token,
			},
			logType: okLog,
		},
		{
			desc: "delete thing with invalid token",
			args: []string{
				deleteCommand,
				thing.ID,
				invalidToken,
			},
			sdkerr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "delete thing with invalid thing ID",
			args: []string{
				deleteCommand,
				invalidID,
				token,
			},
			sdkerr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden).Error()),
			logType:       errLog,
		},
		{
			desc: "delete thing with invalid args",
			args: []string{
				deleteCommand,
				thing.ID,
				extraArg,
			},
			logType: usageLog,
		},
	}

	for _, tc := range cases {
		sdkCall := sdkMock.On("DeleteThing", mock.Anything, mock.Anything).Return(tc.sdkerr)
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

func TestEnableThingCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	enableCommand := "enable"
	thingsCmd := cli.NewThingsCmd()
	rootCmd := setFlags(thingsCmd)
	var tg mgsdk.Thing

	cases := []struct {
		desc          string
		args          []string
		sdkerr        errors.SDKError
		errLogMessage string
		thing         mgsdk.Thing
		logType       outputLog
	}{
		{
			desc: "enable thing successfully",
			args: []string{
				enableCommand,
				thing.ID,
				validToken,
			},
			sdkerr:  nil,
			thing:   thing,
			logType: entityLog,
		},
		{
			desc: "delete thing with invalid token",
			args: []string{
				enableCommand,
				thing.ID,
				invalidToken,
			},
			sdkerr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "delete thing with invalid thing ID",
			args: []string{
				enableCommand,
				invalidID,
				token,
			},
			sdkerr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden).Error()),
			logType:       errLog,
		},
		{
			desc: "enable thing with invalid args",
			args: []string{
				enableCommand,
				thing.ID,
				validToken,
				extraArg,
			},
			logType: usageLog,
		},
	}

	for _, tc := range cases {
		sdkCall := sdkMock.On("EnableThing", tc.args[1], tc.args[2]).Return(tc.thing, tc.sdkerr)
		out := executeCommand(t, rootCmd, tc.args...)

		switch tc.logType {
		case errLog:
			assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
		case usageLog:
			assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
		case entityLog:
			err := json.Unmarshal([]byte(out), &tg)
			assert.Nil(t, err)
			assert.Equal(t, tc.thing, tg, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.thing, tg))
		}

		sdkCall.Unset()
	}
}

func TestDisablethingCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	disableCommand := "disable"
	thingsCmd := cli.NewThingsCmd()
	rootCmd := setFlags(thingsCmd)

	var usr mgsdk.Thing

	cases := []struct {
		desc          string
		args          []string
		sdkerr        errors.SDKError
		errLogMessage string
		thing         mgsdk.Thing
		logType       outputLog
	}{
		{
			desc: "disable thing successfully",
			args: []string{
				disableCommand,
				thing.ID,
				validToken,
			},
			logType: entityLog,
			thing:   thing,
		},
		{
			desc: "delete thing with invalid token",
			args: []string{
				disableCommand,
				thing.ID,
				invalidToken,
			},
			sdkerr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden)),
			logType:       errLog,
		},
		{
			desc: "delete thing with invalid thing ID",
			args: []string{
				disableCommand,
				invalidID,
				token,
			},
			sdkerr:        errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.NewSDKErrorWithStatus(svcerr.ErrAuthorization, http.StatusForbidden).Error()),
			logType:       errLog,
		},
		{
			desc: "disable thing with invalid args",
			args: []string{
				disableCommand,
				thing.ID,
				validToken,
				extraArg,
			},
			logType: usageLog,
		},
	}

	for _, tc := range cases {
		sdkCall := sdkMock.On("DisableThing", tc.args[1], tc.args[2]).Return(tc.thing, tc.sdkerr)
		out := executeCommand(t, rootCmd, tc.args...)

		switch tc.logType {
		case errLog:
			assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
		case usageLog:
			assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
		case entityLog:
			err := json.Unmarshal([]byte(out), &usr)
			if err != nil {
				t.Fatalf("json.Unmarshal failed: %v", err)
			}
			assert.Equal(t, tc.thing, usr, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.thing, usr))
		}

		sdkCall.Unset()
	}
}

func TestUsersthingCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	usersCommand := "users"
	thingsCmd := cli.NewThingsCmd()
	rootCmd := setFlags(thingsCmd)

	page := mgsdk.UsersPage{}

	cases := []struct {
		desc string
		args []string
	}{
		{
			desc: "get thing's users successfully",
			args: []string{
				usersCommand,
				thing.ID,
				token,
			},
		},
	}
}
