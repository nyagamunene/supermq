// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	auth "github.com/absmach/supermq/auth"

	mock "github.com/stretchr/testify/mock"
)

// Cache is an autogenerated mock type for the Cache type
type Cache struct {
	mock.Mock
}

// CheckScope provides a mock function with given fields: ctx, patID, optionalDomainID, entityType, operation, entityID
func (_m *Cache) CheckScope(ctx context.Context, patID string, optionalDomainID string, entityType auth.EntityType, operation auth.Operation, entityID string) (bool, error) {
	ret := _m.Called(ctx, patID, optionalDomainID, entityType, operation, entityID)

	if len(ret) == 0 {
		panic("no return value specified for CheckScope")
	}

	var r0 bool
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, auth.EntityType, auth.Operation, string) (bool, error)); ok {
		return rf(ctx, patID, optionalDomainID, entityType, operation, entityID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, auth.EntityType, auth.Operation, string) bool); ok {
		r0 = rf(ctx, patID, optionalDomainID, entityType, operation, entityID)
	} else {
		r0 = ret.Get(0).(bool)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, auth.EntityType, auth.Operation, string) error); ok {
		r1 = rf(ctx, patID, optionalDomainID, entityType, operation, entityID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Remove provides a mock function with given fields: ctx, scopes
func (_m *Cache) Remove(ctx context.Context, scopes []auth.Scope) error {
	ret := _m.Called(ctx, scopes)

	if len(ret) == 0 {
		panic("no return value specified for Remove")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []auth.Scope) error); ok {
		r0 = rf(ctx, scopes)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Save provides a mock function with given fields: ctx, scopes
func (_m *Cache) Save(ctx context.Context, scopes []auth.Scope) error {
	ret := _m.Called(ctx, scopes)

	if len(ret) == 0 {
		panic("no return value specified for Save")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, []auth.Scope) error); ok {
		r0 = rf(ctx, scopes)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewCache creates a new instance of Cache. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewCache(t interface {
	mock.TestingT
	Cleanup(func())
}) *Cache {
	mock := &Cache{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
