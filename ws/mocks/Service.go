// Code generated by mockery v2.42.1. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	ws "github.com/absmach/magistrala/ws"
	mock "github.com/stretchr/testify/mock"
)

// Service is an autogenerated mock type for the Service type
type Service struct {
	mock.Mock
}

// Subscribe provides a mock function with given fields: ctx, thingKey, chanID, subtopic, client
func (_m *Service) Subscribe(ctx context.Context, thingKey string, chanID string, subtopic string, client *ws.Client) error {
	ret := _m.Called(ctx, thingKey, chanID, subtopic, client)

	if len(ret) == 0 {
		panic("no return value specified for Subscribe")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, *ws.Client) error); ok {
		r0 = rf(ctx, thingKey, chanID, subtopic, client)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewService creates a new instance of Service. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewService(t interface {
	mock.TestingT
	Cleanup(func())
}) *Service {
	mock := &Service{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
