// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/absmach/magistrala/cli"
	"github.com/absmach/magistrala/internal/testsutil"
	"github.com/absmach/magistrala/pkg/errors"
	mgsdk "github.com/absmach/magistrala/pkg/sdk/go"
	sdkmocks "github.com/absmach/magistrala/pkg/sdk/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var channel = mgsdk.Channel{
	ID:       testsutil.GenerateUUID(&testing.T{}),
	Name:     "testchannel",
	DomainID: thing.DomainID,
}

func TestCreateChannelCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	createCommand := "create"
	channelJson := "{\"name\":\"testchannel\", \"metadata\":{\"key1\":\"value1\"}}"
	channelCmd := cli.NewChannelsCmd()
	rootCmd := setFlags(channelCmd)

	cp := mgsdk.Channel{}
	cases := []struct {
		desc string
		args []string
		logType outputLog
		channel mgsdk.Channel
		sdkErr errors.SDKError
		errLogMessage string
	}{
		{
			desc: "create channel successfully",
			args: []string{
				createCommand,
				channelJson,
				token,
			},
			channel: channel,
			logType: entityLog,
		},
		{
			desc: "create channel with invalid args",
			args: []string{
				createCommand,
				channelJson,
				token,
			},
			logType: usageLog,
		},
		{
			desc: "create channel with invalid metadata",
			args: []string{
				createCommand,
				"{\"name\":\"testchannel\", \"metadata\":{\"key1\":\"value1\"}",
				token,
			},
			sdkErr:        errors.NewSDKError(errors.New("unexpected end of JSON input")),
			errLogMessage: fmt.Sprintf("\nerror: %s\n\n", errors.New("unexpected end of JSON input")),
			logType:       errLog,
		},
	}

	for _, tc := range cases {
		sdkCall := sdkMock.On("CreateChannel", mock.Anything, tc.args[2]).Return(tc.channel, tc.sdkErr)
		out := executeCommand(t, rootCmd, tc.args...)

		switch tc.logType {
		case entityLog:
			err := json.Unmarshal([]byte(out), &cp)
			assert.Nil(t,err)
			assert.Equal(t, tc.channel, cp, fmt.Sprintf("%s unexpected response: expected: %v, got: %v", tc.desc, tc.channel, cp))
		case usageLog:
			assert.False(t, strings.Contains(out, rootCmd.Use),fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
		}
		sdkCall.Unset()
	}
}
