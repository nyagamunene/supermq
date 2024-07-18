// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/absmach/magistrala/cli"
	"github.com/absmach/magistrala/pkg/errors"
	sdkmocks "github.com/absmach/magistrala/pkg/sdk/mocks"
	"github.com/stretchr/testify/assert"
)

func TestSendUserInvitationCmd(t *testing.T){
	sdkMock := new(sdkmocks.SDK)
	cli.SetSDK(sdkMock)
	invCmd := cli.NewInvitationsCmd()
	rootCmd := setFlags(invCmd)

	cases:= []struct {
		desc          string
		args          []string
		logType       outputLog
		errLogMessage string
		sdkErr        errors.SDKError
		}{
			{
			desc: "send message successfully",
			args: []string{
				user.ID,
				// domain.ID,
				relation,
				validToken,
			},
			logType: okLog,
		},
	}

	for _, tc := range cases {

		t.Run(tc.desc, func(t *testing.T) {
			out := executeCommand(t, rootCmd, append([]string{sendCmd}, tc.args...)...)
			switch tc.logType {
			case okLog:
				assert.True(t, strings.Contains(out, "ok"), fmt.Sprintf("%s unexpected response: expected success message, got: %v", tc.desc, out))
			case errLog:
				assert.Equal(t, tc.errLogMessage, out, fmt.Sprintf("%s unexpected error response: expected %s got errLogMessage:%s", tc.desc, tc.errLogMessage, out))
			case usageLog:
				assert.False(t, strings.Contains(out, rootCmd.Use), fmt.Sprintf("%s invalid usage: %s", tc.desc, out))
			}
		})
	}
}