// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package cli_test

import (
	"testing"

	mgsdk "github.com/absmach/magistrala/pkg/sdk/go"
	"github.com/absmach/magistrala/internal/testsutil"
)

var channel = mgsdk.Channel{
	ID: testsutil.GenerateUUID(&testing.T{}),
	
}
