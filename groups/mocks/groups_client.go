// Code generated by mockery; DO NOT EDIT.
// github.com/vektra/mockery
// template: testify
// Copyright (c) Abstract Machines

// SPDX-License-Identifier: Apache-2.0

package mocks

import (
	"context"

	"github.com/absmach/supermq/api/grpc/common/v1"
	mock "github.com/stretchr/testify/mock"
	"google.golang.org/grpc"
)

// NewGroupsServiceClient creates a new instance of GroupsServiceClient. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewGroupsServiceClient(t interface {
	mock.TestingT
	Cleanup(func())
}) *GroupsServiceClient {
	mock := &GroupsServiceClient{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}

// GroupsServiceClient is an autogenerated mock type for the GroupsServiceClient type
type GroupsServiceClient struct {
	mock.Mock
}

type GroupsServiceClient_Expecter struct {
	mock *mock.Mock
}

func (_m *GroupsServiceClient) EXPECT() *GroupsServiceClient_Expecter {
	return &GroupsServiceClient_Expecter{mock: &_m.Mock}
}

// RetrieveEntity provides a mock function for the type GroupsServiceClient
func (_mock *GroupsServiceClient) RetrieveEntity(ctx context.Context, in *v1.RetrieveEntityReq, opts ...grpc.CallOption) (*v1.RetrieveEntityRes, error) {
	var tmpRet mock.Arguments
	if len(opts) > 0 {
		tmpRet = _mock.Called(ctx, in, opts)
	} else {
		tmpRet = _mock.Called(ctx, in)
	}
	ret := tmpRet

	if len(ret) == 0 {
		panic("no return value specified for RetrieveEntity")
	}

	var r0 *v1.RetrieveEntityRes
	var r1 error
	if returnFunc, ok := ret.Get(0).(func(context.Context, *v1.RetrieveEntityReq, ...grpc.CallOption) (*v1.RetrieveEntityRes, error)); ok {
		return returnFunc(ctx, in, opts...)
	}
	if returnFunc, ok := ret.Get(0).(func(context.Context, *v1.RetrieveEntityReq, ...grpc.CallOption) *v1.RetrieveEntityRes); ok {
		r0 = returnFunc(ctx, in, opts...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*v1.RetrieveEntityRes)
		}
	}
	if returnFunc, ok := ret.Get(1).(func(context.Context, *v1.RetrieveEntityReq, ...grpc.CallOption) error); ok {
		r1 = returnFunc(ctx, in, opts...)
	} else {
		r1 = ret.Error(1)
	}
	return r0, r1
}

// GroupsServiceClient_RetrieveEntity_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'RetrieveEntity'
type GroupsServiceClient_RetrieveEntity_Call struct {
	*mock.Call
}

// RetrieveEntity is a helper method to define mock.On call
//   - ctx context.Context
//   - in *v1.RetrieveEntityReq
//   - opts ...grpc.CallOption
func (_e *GroupsServiceClient_Expecter) RetrieveEntity(ctx interface{}, in interface{}, opts ...interface{}) *GroupsServiceClient_RetrieveEntity_Call {
	return &GroupsServiceClient_RetrieveEntity_Call{Call: _e.mock.On("RetrieveEntity",
		append([]interface{}{ctx, in}, opts...)...)}
}

func (_c *GroupsServiceClient_RetrieveEntity_Call) Run(run func(ctx context.Context, in *v1.RetrieveEntityReq, opts ...grpc.CallOption)) *GroupsServiceClient_RetrieveEntity_Call {
	_c.Call.Run(func(args mock.Arguments) {
		var arg0 context.Context
		if args[0] != nil {
			arg0 = args[0].(context.Context)
		}
		var arg1 *v1.RetrieveEntityReq
		if args[1] != nil {
			arg1 = args[1].(*v1.RetrieveEntityReq)
		}
		var arg2 []grpc.CallOption
		var variadicArgs []grpc.CallOption
		if len(args) > 2 {
			variadicArgs = args[2].([]grpc.CallOption)
		}
		arg2 = variadicArgs
		run(
			arg0,
			arg1,
			arg2...,
		)
	})
	return _c
}

func (_c *GroupsServiceClient_RetrieveEntity_Call) Return(retrieveEntityRes *v1.RetrieveEntityRes, err error) *GroupsServiceClient_RetrieveEntity_Call {
	_c.Call.Return(retrieveEntityRes, err)
	return _c
}

func (_c *GroupsServiceClient_RetrieveEntity_Call) RunAndReturn(run func(ctx context.Context, in *v1.RetrieveEntityReq, opts ...grpc.CallOption) (*v1.RetrieveEntityRes, error)) *GroupsServiceClient_RetrieveEntity_Call {
	_c.Call.Return(run)
	return _c
}
