// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"fmt"
	"testing"

	"github.com/absmach/magistrala/cli"
	"github.com/absmach/magistrala/pkg/errors"
	sdkmocks "github.com/absmach/magistrala/pkg/sdk/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestCreateBootstrapConfigCmd(t *testing.T) {
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	bootCmd := cli.NewBootstrapCmd()
	rootCmd := setFlags(bootCmd)

	cases := []struct{
		desc string
		args []string
		logType outputLog
		response string
		sdkErr errors.SDKError
		errLogMessage string
		id string
	}{
		{
			desc: "create bootstrap config successfully",

			logType: createLog,
			id:       thing.ID,
			response: fmt.Sprintf("\ncreated: %s\n\n", thing.ID),
		},
	}

	for _, tc := range cases{
		t.Run(tc.desc, func(t *testing.T) {
			sdkCall := sdkMock.On("AddBootstrap", mock.Anything, mock.Anything).Return(tc.id, tc.sdkErr)
			out := executeCommand(t, rootCmd, tc.args...)

			switch tc.logType{
			case createLog:
				assert.Equal(t, tc.response, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.response, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))	
			}
			sdkCall.Unset()
		})
	}

}