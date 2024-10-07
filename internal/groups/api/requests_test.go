// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"strings"
	"testing"

	"github.com/absmach/magistrala/internal/api"
	"github.com/absmach/magistrala/pkg/apiutil"
	"github.com/absmach/magistrala/pkg/groups"
	"github.com/absmach/magistrala/pkg/policies"
	"github.com/stretchr/testify/assert"
)

var valid = "valid"

func TestCreateGroupReqValidation(t *testing.T) {
	cases := []struct {
		desc string
		req  createGroupReq
		err  error
	}{
		{
			desc: "valid request",
			req: createGroupReq{
				domainID: valid,
				Group: groups.Group{
					Name: valid,
				},
			},
			err: nil,
		},
		{
			desc: "empty domain id",
			req: createGroupReq{
				domainID: "",
				Group: groups.Group{
					Name: valid,
				},
			},
			err: apiutil.ErrMissingDomainID,
		},
		{
			desc: "long name",
			req: createGroupReq{
				domainID: valid,
				Group: groups.Group{
					Name: strings.Repeat("a", api.MaxNameSize+1),
				},
			},
			err: apiutil.ErrNameSize,
		},
		{
			desc: "empty name",
			req: createGroupReq{
				domainID: valid,
				Group:    groups.Group{},
			},
			err: apiutil.ErrNameSize,
		},
	}

	for _, tc := range cases {
		err := tc.req.validate()
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestUpdateGroupReqValidation(t *testing.T) {
	cases := []struct {
		desc string
		req  updateGroupReq
		err  error
	}{
		{
			desc: "valid request",
			req: updateGroupReq{
				id:       valid,
				domainID: valid,
				Name:     valid,
			},
			err: nil,
		},
		{
			desc: "long name",
			req: updateGroupReq{
				id:       valid,
				domainID: valid,
				Name:     strings.Repeat("a", api.MaxNameSize+1),
			},
			err: apiutil.ErrNameSize,
		},
		{
			desc: "empty id",
			req: updateGroupReq{
				domainID: valid,
				Name:     valid,
			},
			err: apiutil.ErrMissingID,
		},
		{
			desc: "empty domain id",
			req: updateGroupReq{
				id:       valid,
				domainID: "",
				Name:     valid,
			},
			err: apiutil.ErrMissingDomainID,
		},
	}

	for _, tc := range cases {
		err := tc.req.validate()
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestListGroupReqValidation(t *testing.T) {
	cases := []struct {
		desc string
		req  listGroupsReq
		err  error
	}{
		{
			desc: "valid request",
			req: listGroupsReq{
				memberKind: policies.ThingsKind,
				memberID:   valid,
				domainID:   valid,
				Page: groups.Page{
					PageMeta: groups.PageMeta{
						Limit: 10,
					},
				},
			},
			err: nil,
		},
		{
			desc: "empty domain id",
			req: listGroupsReq{
				memberKind: auth.ThingsKind,
				memberID:   valid,
				domainID:   "",
				Page: groups.Page{
					PageMeta: groups.PageMeta{
						Limit: 10,
					},
				},
			},
			err: apiutil.ErrMissingDomainID,
		},
		{
			desc: "empty memberkind",
			req: listGroupsReq{
				memberID: valid,
				domainID: valid,
				Page: groups.Page{
					PageMeta: groups.PageMeta{
						Limit: 10,
					},
				},
			},
			err: apiutil.ErrMissingMemberKind,
		},
		{
			desc: "empty member id",
			req: listGroupsReq{
				memberKind: policies.ThingsKind,
				domainID:   valid,
				Page: groups.Page{
					PageMeta: groups.PageMeta{
						Limit: 10,
					},
				},
			},
			err: apiutil.ErrMissingID,
		},
		{
			desc: "invalid upper level",
			req: listGroupsReq{
				memberKind: policies.ThingsKind,
				memberID:   valid,
				domainID:   valid,
				Page: groups.Page{
					PageMeta: groups.PageMeta{
						Limit: 10,
					},
					Level: groups.MaxLevel + 1,
				},
			},
			err: apiutil.ErrInvalidLevel,
		},
		{
			desc: "invalid lower limit",
			req: listGroupsReq{
				memberKind: policies.ThingsKind,
				memberID:   valid,
				domainID:   valid,
				Page: groups.Page{
					PageMeta: groups.PageMeta{
						Limit: 0,
					},
				},
			},
			err: apiutil.ErrLimitSize,
		},
		{
			desc: "invalid upper limit",
			req: listGroupsReq{
				memberKind: policies.ThingsKind,
				memberID:   valid,
				domainID:   valid,
				Page: groups.Page{
					PageMeta: groups.PageMeta{
						Limit: api.MaxLimitSize + 1,
					},
				},
			},
			err: apiutil.ErrLimitSize,
		},
	}

	for _, tc := range cases {
		err := tc.req.validate()
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestGroupReqValidation(t *testing.T) {
	cases := []struct {
		desc string
		req  groupReq
		err  error
	}{
		{
			desc: "valid request",
			req: groupReq{
				id:       valid,
				domainID: valid,
			},
			err: nil,
		},
		{
			desc: "empty id",
			req: groupReq{
				domainID: valid,
			},
			err: apiutil.ErrMissingID,
		},
		{
			desc: "empty domain id",
			req: groupReq{
				id:       valid,
				domainID: "",
			},
			err: apiutil.ErrMissingDomainID,
		},
	}

	for _, tc := range cases {
		err := tc.req.validate()
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestGroupPermsReqValidation(t *testing.T) {
	cases := []struct {
		desc string
		req  groupPermsReq
		err  error
	}{
		{
			desc: "valid request",
			req: groupPermsReq{
				id:       valid,
				domainID: valid,
			},
			err: nil,
		},
		{
			desc: "empty id",
			req: groupPermsReq{
				domainID: valid,
			},
			err: apiutil.ErrMissingID,
		},
		{
			desc: "empty domain id",
			req: groupPermsReq{
				id:       valid,
				domainID: "",
			},
			err: apiutil.ErrMissingDomainID,
		},
	}

	for _, tc := range cases {
		err := tc.req.validate()
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestChangeGroupStatusReqValidation(t *testing.T) {
	cases := []struct {
		desc string
		req  changeGroupStatusReq
		err  error
	}{
		{
			desc: "valid request",
			req: changeGroupStatusReq{
				id:       valid,
				domainID: valid,
			},
			err: nil,
		},
		{
			desc: "empty id",
			req: changeGroupStatusReq{
				domainID: valid,
			},
			err: apiutil.ErrMissingID,
		},
		{
			desc: "empty domain id",
			req: changeGroupStatusReq{
				id:       valid,
				domainID: "",
			},
			err: apiutil.ErrMissingDomainID,
		},
	}

	for _, tc := range cases {
		err := tc.req.validate()
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestAssignReqValidation(t *testing.T) {
	cases := []struct {
		desc string
		req  assignReq
		err  error
	}{
		{
			desc: "valid request",
			req: assignReq{
				groupID:    valid,
				domainID:   valid,
				Relation:   policies.ContributorRelation,
				MemberKind: policies.ThingsKind,
				Members:    []string{valid},
			},
			err: nil,
		},
		{
			desc: "empty member kind",
			req: assignReq{
				groupID:  valid,
				domainID: valid,
				Relation: policies.ContributorRelation,
				Members:  []string{valid},
			},
			err: apiutil.ErrMissingMemberKind,
		},
		{
			desc: "empty groupID",
			req: assignReq{
				domainID:   valid,
				Relation:   policies.ContributorRelation,
				MemberKind: policies.ThingsKind,
				Members:    []string{valid},
			},
			err: apiutil.ErrMissingID,
		},
		{
			desc: "empty Members",
			req: assignReq{
				groupID:    valid,
				domainID:   valid,
				Relation:   policies.ContributorRelation,
				MemberKind: policies.ThingsKind,
			},
			err: apiutil.ErrEmptyList,
		},
		{
			desc: "empty domain id",
			req: assignReq{
				groupID:    valid,
				domainID:   "",
				Relation:   auth.ContributorRelation,
				MemberKind: auth.ThingsKind,
				Members:    []string{valid},
			},
			err: apiutil.ErrMissingDomainID,
		},
	}

	for _, tc := range cases {
		err := tc.req.validate()
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestUnAssignReqValidation(t *testing.T) {
	cases := []struct {
		desc string
		req  unassignReq
		err  error
	}{
		{
			desc: "valid request",
			req: unassignReq{
				groupID:    valid,
				domainID:   valid,
				Relation:   policies.ContributorRelation,
				MemberKind: policies.ThingsKind,
				Members:    []string{valid},
			},
			err: nil,
		},
		{
			desc: "empty member kind",
			req: unassignReq{
				groupID:  valid,
				domainID: valid,
				Relation: policies.ContributorRelation,
				Members:  []string{valid},
			},
			err: apiutil.ErrMissingMemberKind,
		},
		{
			desc: "empty groupID",
			req: unassignReq{
				domainID:   valid,
				Relation:   policies.ContributorRelation,
				MemberKind: policies.ThingsKind,
				Members:    []string{valid},
			},
			err: apiutil.ErrMissingID,
		},
		{
			desc: "empty Members",
			req: unassignReq{
				groupID:    valid,
				domainID:   valid,
				Relation:   policies.ContributorRelation,
				MemberKind: policies.ThingsKind,
			},
			err: apiutil.ErrEmptyList,
		},
		{
			desc: "empty domain id",
			req: unassignReq{
				groupID:    valid,
				domainID:   "",
				Relation:   auth.ContributorRelation,
				MemberKind: auth.ThingsKind,
				Members:    []string{valid},
			},
			err: apiutil.ErrMissingDomainID,
		},
	}

	for _, tc := range cases {
		err := tc.req.validate()
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}

func TestListMembersReqValidation(t *testing.T) {
	cases := []struct {
		desc string
		req  listMembersReq
		err  error
	}{
		{
			desc: "valid request",
			req: listMembersReq{
				groupID:    valid,
				domainID:   valid,
				permission: policies.ViewPermission,
				memberKind: policies.ThingsKind,
			},
			err: nil,
		},
		{
			desc: "empty member kind",
			req: listMembersReq{
				groupID:    valid,
				domainID:   valid,
				permission: policies.ViewPermission,
			},
			err: apiutil.ErrMissingMemberKind,
		},
		{
			desc: "empty groupID",
			req: listMembersReq{
				domainID:   valid,
				permission: policies.ViewPermission,
				memberKind: policies.ThingsKind,
			},
			err: apiutil.ErrMissingID,
		},
		{
			desc: "empty domain id",
			req: listMembersReq{
				groupID:    valid,
				domainID:   "",
				permission: auth.ViewPermission,
				memberKind: auth.ThingsKind,
			},
			err: apiutil.ErrMissingDomainID,
		},
	}

	for _, tc := range cases {
		err := tc.req.validate()
		assert.Equal(t, tc.err, err, fmt.Sprintf("%s: expected %s got %s\n", tc.desc, tc.err, err))
	}
}
