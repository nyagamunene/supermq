// Code generated by mockery v2.42.1. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	twins "github.com/absmach/magistrala/twins"
	mock "github.com/stretchr/testify/mock"
)

// StateRepository is an autogenerated mock type for the StateRepository type
type StateRepository struct {
	mock.Mock
}

// Count provides a mock function with given fields: ctx, twin
func (_m *StateRepository) Count(ctx context.Context, twin twins.Twin) (int64, error) {
	ret := _m.Called(ctx, twin)

	if len(ret) == 0 {
		panic("no return value specified for Count")
	}

	var r0 int64
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, twins.Twin) (int64, error)); ok {
		return rf(ctx, twin)
	}
	if rf, ok := ret.Get(0).(func(context.Context, twins.Twin) int64); ok {
		r0 = rf(ctx, twin)
	} else {
		r0 = ret.Get(0).(int64)
	}

	if rf, ok := ret.Get(1).(func(context.Context, twins.Twin) error); ok {
		r1 = rf(ctx, twin)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveAll provides a mock function with given fields: ctx, offset, limit, twinID
func (_m *StateRepository) RetrieveAll(ctx context.Context, offset uint64, limit uint64, twinID string) (twins.StatesPage, error) {
	ret := _m.Called(ctx, offset, limit, twinID)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveAll")
	}

	var r0 twins.StatesPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, uint64, uint64, string) (twins.StatesPage, error)); ok {
		return rf(ctx, offset, limit, twinID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, uint64, uint64, string) twins.StatesPage); ok {
		r0 = rf(ctx, offset, limit, twinID)
	} else {
		r0 = ret.Get(0).(twins.StatesPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, uint64, uint64, string) error); ok {
		r1 = rf(ctx, offset, limit, twinID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrieveLast provides a mock function with given fields: ctx, twinID
func (_m *StateRepository) RetrieveLast(ctx context.Context, twinID string) (twins.State, error) {
	ret := _m.Called(ctx, twinID)

	if len(ret) == 0 {
		panic("no return value specified for RetrieveLast")
	}

	var r0 twins.State
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (twins.State, error)); ok {
		return rf(ctx, twinID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) twins.State); ok {
		r0 = rf(ctx, twinID)
	} else {
		r0 = ret.Get(0).(twins.State)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, twinID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Save provides a mock function with given fields: ctx, state
func (_m *StateRepository) Save(ctx context.Context, state twins.State) error {
	ret := _m.Called(ctx, state)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, twins.State) error); ok {
		r0 = rf(ctx, state)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Update provides a mock function with given fields: ctx, state
func (_m *StateRepository) Update(ctx context.Context, state twins.State) error {
	ret := _m.Called(ctx, state)

	if len(ret) == 0 {
		panic("no return value specified for Update")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, twins.State) error); ok {
		r0 = rf(ctx, state)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewStateRepository creates a new instance of StateRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewStateRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *StateRepository {
	mock := &StateRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
