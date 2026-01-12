// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"testing"

	"github.com/absmach/supermq/auth"
	"github.com/stretchr/testify/assert"
)

func TestOperationString(t *testing.T) {
	cases := []struct {
		desc     string
		op       auth.Operation
		expected string
	}{
		{
			desc:     "Client create operation",
			op:       auth.ClientCreateOp,
			expected: auth.ClientCreateOp.String(),
		},
		{
			desc:     "Client view operation",
			op:       auth.ClientViewOp,
			expected: auth.ClientViewOp.String(),
		},
		{
			desc:     "Client list operation",
			op:       auth.ClientListOp,
			expected: auth.ClientListOp.String(),
		},
		{
			desc:     "Client update operation",
			op:       auth.ClientUpdateOp,
			expected: auth.ClientUpdateOp.String(),
		},
		{
			desc:     "Client delete operation",
			op:       auth.ClientDeleteOp,
			expected: auth.ClientDeleteOp.String(),
		},
		{
			desc:     "Dashboard share operation",
			op:       auth.DashboardShareOp,
			expected: auth.DashboardShareOp.String(),
		},
		{
			desc:     "Dashboard unshare operation",
			op:       auth.DashboardUnshareOp,
			expected: auth.DashboardUnshareOp.String(),
		},
		{
			desc:     "Message publish operation",
			op:       auth.MessagePublishOp,
			expected: auth.MessagePublishOp.String(),
		},
		{
			desc:     "Message subscribe operation",
			op:       auth.MessageSubscribeOp,
			expected: auth.MessageSubscribeOp.String(),
		},
		{
			desc:     "Unknown operation",
			op:       auth.Operation(9999),
			expected: "unknown operation type 9999",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := tc.op.String()
			assert.Equal(t, tc.expected, got, "String() = %v, expected %v", got, tc.expected)
		})
	}
}

func TestOperationValidString(t *testing.T) {
	cases := []struct {
		desc     string
		op       auth.Operation
		expected string
		err      bool
	}{
		{
			desc:     "Valid client create operation",
			op:       auth.ClientCreateOp,
			expected: auth.ClientCreateOp.String(),
			err:      false,
		},
		{
			desc:     "Valid client view operation",
			op:       auth.ClientViewOp,
			expected: auth.ClientViewOp.String(),
			err:      false,
		},
		{
			desc:     "Invalid operation",
			op:       auth.Operation(9999),
			expected: "",
			err:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := tc.op.ValidString()
			if tc.err {
				assert.Error(t, err, "ValidString() should return error")
			} else {
				assert.NoError(t, err, "ValidString() should not return error")
				assert.Equal(t, tc.expected, got, "ValidString() = %v, expected %v", got, tc.expected)
			}
		})
	}
}

func TestParseOperation(t *testing.T) {
	cases := []struct {
		desc     string
		op       string
		expected auth.Operation
		err      bool
	}{
		{
			desc:     "Parse client_create",
			op:       auth.ClientCreateOp.String(),
			expected: auth.ClientCreateOp,
			err:      false,
		},
		{
			desc:     "Parse client_view",
			op:       auth.ClientViewOp.String(),
			expected: auth.ClientViewOp,
			err:      false,
		},
		{
			desc:     "Parse client_list",
			op:       auth.ClientListOp.String(),
			expected: auth.ClientListOp,
			err:      false,
		},
		{
			desc:     "Parse client_update",
			op:       auth.ClientUpdateOp.String(),
			expected: auth.ClientUpdateOp,
			err:      false,
		},
		{
			desc:     "Parse client_delete",
			op:       auth.ClientDeleteOp.String(),
			expected: auth.ClientDeleteOp,
			err:      false,
		},
		{
			desc:     "Parse dashboard_share",
			op:       auth.DashboardShareOp.String(),
			expected: auth.DashboardShareOp,
			err:      false,
		},
		{
			desc:     "Parse dashboard_unshare",
			op:       auth.DashboardUnshareOp.String(),
			expected: auth.DashboardUnshareOp,
			err:      false,
		},
		{
			desc:     "Parse message_publish",
			op:       auth.MessagePublishOp.String(),
			expected: auth.MessagePublishOp,
			err:      false,
		},
		{
			desc:     "Parse message_subscribe",
			op:       auth.MessageSubscribeOp.String(),
			expected: auth.MessageSubscribeOp,
			err:      false,
		},
		{
			desc:     "Parse unknown operation",
			op:       "unknown",
			expected: auth.Operation(0),
			err:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := auth.ParseOperation(tc.op)
			if tc.err {
				assert.Error(t, err, "ParseOperation() should return error")
			} else {
				assert.NoError(t, err, "ParseOperation() should not return error")
				assert.Equal(t, tc.expected, got, "ParseOperation() = %v, expected %v", got, tc.expected)
			}
		})
	}
}

func TestOperationMarshalJSON(t *testing.T) {
	cases := []struct {
		desc     string
		op       auth.Operation
		expected []byte
		err      error
	}{
		{
			desc:     "Marshal client_create",
			op:       auth.ClientCreateOp,
			expected: []byte(`"` + auth.ClientCreateOp.String() + `"`),
			err:      nil,
		},
		{
			desc:     "Marshal client_view",
			op:       auth.ClientViewOp,
			expected: []byte(`"` + auth.ClientViewOp.String() + `"`),
			err:      nil,
		},
		{
			desc:     "Marshal client_delete",
			op:       auth.ClientDeleteOp,
			expected: []byte(`"` + auth.ClientDeleteOp.String() + `"`),
			err:      nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := tc.op.MarshalJSON()
			assert.Equal(t, tc.err, err, "MarshalJSON() error = %v, expected %v", err, tc.err)
			assert.Equal(t, tc.expected, got, "MarshalJSON() = %v, expected %v", got, tc.expected)
		})
	}
}

func TestOperationUnmarshalJSON(t *testing.T) {
	cases := []struct {
		desc     string
		data     []byte
		expected auth.Operation
		err      bool
	}{
		{
			desc:     "Unmarshal client_create",
			data:     []byte(`"` + auth.ClientCreateOp.String() + `"`),
			expected: auth.ClientCreateOp,
			err:      false,
		},
		{
			desc:     "Unmarshal client_view",
			data:     []byte(`"` + auth.ClientViewOp.String() + `"`),
			expected: auth.ClientViewOp,
			err:      false,
		},
		{
			desc:     "Unmarshal unknown",
			data:     []byte(`"unknown"`),
			expected: auth.Operation(0),
			err:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			var op auth.Operation
			err := op.UnmarshalJSON(tc.data)
			if tc.err {
				assert.Error(t, err, "UnmarshalJSON() should return error")
			} else {
				assert.NoError(t, err, "UnmarshalJSON() should not return error")
				assert.Equal(t, tc.expected, op, "UnmarshalJSON() = %v, expected %v", op, tc.expected)
			}
		})
	}
}

func TestOperationMarshalText(t *testing.T) {
	cases := []struct {
		desc     string
		op       auth.Operation
		expected []byte
		err      error
	}{
		{
			desc:     "Marshal client_create as text",
			op:       auth.ClientCreateOp,
			expected: []byte(auth.ClientCreateOp.String()),
			err:      nil,
		},
		{
			desc:     "Marshal client_view as text",
			op:       auth.ClientViewOp,
			expected: []byte(auth.ClientViewOp.String()),
			err:      nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := tc.op.MarshalText()
			assert.Equal(t, tc.err, err, "MarshalText() error = %v, expected %v", err, tc.err)
			assert.Equal(t, tc.expected, got, "MarshalText() = %v, expected %v", got, tc.expected)
		})
	}
}

func TestOperationUnmarshalText(t *testing.T) {
	cases := []struct {
		desc     string
		data     []byte
		expected auth.Operation
		err      bool
	}{
		{
			desc:     "Unmarshal client_create from text",
			data:     []byte(auth.ClientCreateOp.String()),
			expected: auth.ClientCreateOp,
			err:      false,
		},
		{
			desc:     "Unmarshal client_view from text",
			data:     []byte(auth.ClientViewOp.String()),
			expected: auth.ClientViewOp,
			err:      false,
		},
		{
			desc:     "Unmarshal unknown from text",
			data:     []byte("unknown"),
			expected: auth.Operation(0),
			err:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			var op auth.Operation
			err := op.UnmarshalText(tc.data)
			if tc.err {
				assert.Error(t, err, "UnmarshalText() should return error")
			} else {
				assert.NoError(t, err, "UnmarshalText() should not return error")
				assert.Equal(t, tc.expected, op, "UnmarshalText() = %v, expected %v", op, tc.expected)
			}
		})
	}
}

func TestEntityTypeString(t *testing.T) {
	cases := []struct {
		desc     string
		et       auth.EntityType
		expected string
	}{
		{
			desc:     "Groups entity type",
			et:       auth.GroupsType,
			expected: "groups",
		},
		{
			desc:     "Channels entity type",
			et:       auth.ChannelsType,
			expected: "channels",
		},
		{
			desc:     "Clients entity type",
			et:       auth.ClientsType,
			expected: "clients",
		},
		{
			desc:     "Dashboard entity type",
			et:       auth.DashboardType,
			expected: "dashboards",
		},
		{
			desc:     "Messages entity type",
			et:       auth.MessagesType,
			expected: "messages",
		},
		{
			desc:     "Unknown entity type",
			et:       auth.EntityType(100),
			expected: "unknown domain entity type 100",
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := tc.et.String()
			assert.Equal(t, tc.expected, got, "String() = %v, expected %v", got, tc.expected)
		})
	}
}

func TestParseEntityType(t *testing.T) {
	cases := []struct {
		desc     string
		et       string
		expected auth.EntityType
		err      bool
	}{
		{
			desc:     "Parse groups",
			et:       "groups",
			expected: auth.GroupsType,
			err:      false,
		},
		{
			desc:     "Parse channels",
			et:       "channels",
			expected: auth.ChannelsType,
			err:      false,
		},
		{
			desc:     "Parse clients",
			et:       "clients",
			expected: auth.ClientsType,
			err:      false,
		},
		{
			desc:     "Parse dashboards",
			et:       "dashboards",
			expected: auth.DashboardType,
			err:      false,
		},
		{
			desc:     "Parse unknown entity type",
			et:       "unknown",
			expected: auth.EntityType(0),
			err:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := auth.ParseEntityType(tc.et)
			if tc.err {
				assert.Error(t, err, "ParseEntityType() should return error")
			} else {
				assert.NoError(t, err, "ParseEntityType() should not return error")
				assert.Equal(t, tc.expected, got, "ParseEntityType() = %v, expected %v", got, tc.expected)
			}
		})
	}
}

func TestEntityTypeMarshalJSON(t *testing.T) {
	cases := []struct {
		desc     string
		et       auth.EntityType
		expected []byte
		err      error
	}{
		{
			desc:     "Marshal groups",
			et:       auth.GroupsType,
			expected: []byte(`"groups"`),
			err:      nil,
		},
		{
			desc:     "Marshal channels",
			et:       auth.ChannelsType,
			expected: []byte(`"channels"`),
			err:      nil,
		},
		{
			desc:     "Marshal clients",
			et:       auth.ClientsType,
			expected: []byte(`"clients"`),
			err:      nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := tc.et.MarshalJSON()
			assert.Equal(t, tc.err, err, "MarshalJSON() error = %v, expected %v", err, tc.err)
			assert.Equal(t, tc.expected, got, "MarshalJSON() = %v, expected %v", got, tc.expected)
		})
	}
}

func TestEntityTypeUnmarshalJSON(t *testing.T) {
	cases := []struct {
		desc     string
		data     []byte
		expected auth.EntityType
		err      bool
	}{
		{
			desc:     "Unmarshal groups",
			data:     []byte(`"groups"`),
			expected: auth.GroupsType,
			err:      false,
		},
		{
			desc:     "Unmarshal channels",
			data:     []byte(`"channels"`),
			expected: auth.ChannelsType,
			err:      false,
		},
		{
			desc:     "Unmarshal unknown",
			data:     []byte(`"unknown"`),
			expected: auth.EntityType(0),
			err:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			var et auth.EntityType
			err := et.UnmarshalJSON(tc.data)
			if tc.err {
				assert.Error(t, err, "UnmarshalJSON() should return error")
			} else {
				assert.NoError(t, err, "UnmarshalJSON() should not return error")
				assert.Equal(t, tc.expected, et, "UnmarshalJSON() = %v, expected %v", et, tc.expected)
			}
		})
	}
}

func TestEntityTypeMarshalText(t *testing.T) {
	cases := []struct {
		desc     string
		et       auth.EntityType
		expected []byte
		err      error
	}{
		{
			desc:     "Marshal groups as text",
			et:       auth.GroupsType,
			expected: []byte("groups"),
			err:      nil,
		},
		{
			desc:     "Marshal channels as text",
			et:       auth.ChannelsType,
			expected: []byte("channels"),
			err:      nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := tc.et.MarshalText()
			assert.Equal(t, tc.err, err, "MarshalText() error = %v, expected %v", err, tc.err)
			assert.Equal(t, tc.expected, got, "MarshalText() = %v, expected %v", got, tc.expected)
		})
	}
}

func TestEntityTypeUnmarshalText(t *testing.T) {
	cases := []struct {
		desc     string
		data     []byte
		expected auth.EntityType
		err      bool
	}{
		{
			desc:     "Unmarshal groups from text",
			data:     []byte("groups"),
			expected: auth.GroupsType,
			err:      false,
		},
		{
			desc:     "Unmarshal channels from text",
			data:     []byte("channels"),
			expected: auth.ChannelsType,
			err:      false,
		},
		{
			desc:     "Unmarshal unknown from text",
			data:     []byte("unknown"),
			expected: auth.EntityType(0),
			err:      true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			var et auth.EntityType
			err := et.UnmarshalText(tc.data)
			if tc.err {
				assert.Error(t, err, "UnmarshalText() should return error")
			} else {
				assert.NoError(t, err, "UnmarshalText() should not return error")
				assert.Equal(t, tc.expected, et, "UnmarshalText() = %v, expected %v", et, tc.expected)
			}
		})
	}
}
