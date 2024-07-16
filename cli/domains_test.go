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

var domain = mgsdk.Domain{
	ID:   testsutil.GenerateUUID(&testing.T{}),
	Name: "testdomain",
	Alias: "alias",
}

func TestCreateDomainsCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	createCommand := "create"
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
			domain: domain,
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
		
	}

	for _, tc := range cases {
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
	}
}
