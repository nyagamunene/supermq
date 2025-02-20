// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	auth "github.com/absmach/supermq/auth"

	mock "github.com/stretchr/testify/mock"

	time "time"
)

// PATS is an autogenerated mock type for the PATS type
type PATS struct {
	mock.Mock
}

// AddScopeEntry provides a mock function with given fields: ctx, token, patID, scope
func (_m *PATS) AddScopeEntry(ctx context.Context, token string, patID string, scope []auth.Scope) error {
	ret := _m.Called(ctx, token, patID, scope)

	if len(ret) == 0 {
		panic("no return value specified for AddScopeEntry")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, []auth.Scope) error); ok {
		r0 = rf(ctx, token, patID, scope)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// AuthorizePAT provides a mock function with given fields: ctx, userID, patID, entityType, optionalDomainID, operation, entityID
func (_m *PATS) AuthorizePAT(ctx context.Context, userID string, patID string, entityType auth.EntityType, optionalDomainID string, operation auth.Operation, entityID string) error {
	ret := _m.Called(ctx, userID, patID, entityType, optionalDomainID, operation, entityID)

	if len(ret) == 0 {
		panic("no return value specified for AuthorizePAT")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, auth.EntityType, string, auth.Operation, string) error); ok {
		r0 = rf(ctx, userID, patID, entityType, optionalDomainID, operation, entityID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ClearAllScopeEntry provides a mock function with given fields: ctx, token, patID
func (_m *PATS) ClearAllScopeEntry(ctx context.Context, token string, patID string) error {
	ret := _m.Called(ctx, token, patID)

	if len(ret) == 0 {
		panic("no return value specified for ClearAllScopeEntry")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, token, patID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// CreatePAT provides a mock function with given fields: ctx, token, name, description, duration
func (_m *PATS) CreatePAT(ctx context.Context, token string, name string, description string, duration time.Duration) (auth.PAT, error) {
	ret := _m.Called(ctx, token, name, description, duration)

	if len(ret) == 0 {
		panic("no return value specified for CreatePAT")
	}

	var r0 auth.PAT
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, time.Duration) (auth.PAT, error)); ok {
		return rf(ctx, token, name, description, duration)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, time.Duration) auth.PAT); ok {
		r0 = rf(ctx, token, name, description, duration)
	} else {
		r0 = ret.Get(0).(auth.PAT)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string, time.Duration) error); ok {
		r1 = rf(ctx, token, name, description, duration)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeletePAT provides a mock function with given fields: ctx, token, patID
func (_m *PATS) DeletePAT(ctx context.Context, token string, patID string) error {
	ret := _m.Called(ctx, token, patID)

	if len(ret) == 0 {
		panic("no return value specified for DeletePAT")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, token, patID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// IdentifyPAT provides a mock function with given fields: ctx, paToken
func (_m *PATS) IdentifyPAT(ctx context.Context, paToken string) (auth.PAT, error) {
	ret := _m.Called(ctx, paToken)

	if len(ret) == 0 {
		panic("no return value specified for IdentifyPAT")
	}

	var r0 auth.PAT
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (auth.PAT, error)); ok {
		return rf(ctx, paToken)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) auth.PAT); ok {
		r0 = rf(ctx, paToken)
	} else {
		r0 = ret.Get(0).(auth.PAT)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, paToken)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListPATS provides a mock function with given fields: ctx, token, pm
func (_m *PATS) ListPATS(ctx context.Context, token string, pm auth.PATSPageMeta) (auth.PATSPage, error) {
	ret := _m.Called(ctx, token, pm)

	if len(ret) == 0 {
		panic("no return value specified for ListPATS")
	}

	var r0 auth.PATSPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, auth.PATSPageMeta) (auth.PATSPage, error)); ok {
		return rf(ctx, token, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, auth.PATSPageMeta) auth.PATSPage); ok {
		r0 = rf(ctx, token, pm)
	} else {
		r0 = ret.Get(0).(auth.PATSPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, auth.PATSPageMeta) error); ok {
		r1 = rf(ctx, token, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListScopes provides a mock function with given fields: ctx, token, pm
func (_m *PATS) ListScopes(ctx context.Context, token string, pm auth.ScopesPageMeta) (auth.ScopesPage, error) {
	ret := _m.Called(ctx, token, pm)

	if len(ret) == 0 {
		panic("no return value specified for ListScopes")
	}

	var r0 auth.ScopesPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, auth.ScopesPageMeta) (auth.ScopesPage, error)); ok {
		return rf(ctx, token, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, auth.ScopesPageMeta) auth.ScopesPage); ok {
		r0 = rf(ctx, token, pm)
	} else {
		r0 = ret.Get(0).(auth.ScopesPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, auth.ScopesPageMeta) error); ok {
		r1 = rf(ctx, token, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RemoveScopeEntry provides a mock function with given fields: ctx, token, patID, scopeID
func (_m *PATS) RemoveScopeEntry(ctx context.Context, token string, patID string, scopeID ...string) error {
	_va := make([]interface{}, len(scopeID))
	for _i := range scopeID {
		_va[_i] = scopeID[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, token, patID)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for RemoveScopeEntry")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, ...string) error); ok {
		r0 = rf(ctx, token, patID, scopeID...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// ResetPATSecret provides a mock function with given fields: ctx, token, patID, duration
func (_m *PATS) ResetPATSecret(ctx context.Context, token string, patID string, duration time.Duration) (auth.PAT, error) {
	ret := _m.Called(ctx, token, patID, duration)

	if len(ret) == 0 {
		panic("no return value specified for ResetPATSecret")
	}

	var r0 auth.PAT
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, time.Duration) (auth.PAT, error)); ok {
		return rf(ctx, token, patID, duration)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, time.Duration) auth.PAT); ok {
		r0 = rf(ctx, token, patID, duration)
	} else {
		r0 = ret.Get(0).(auth.PAT)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, time.Duration) error); ok {
		r1 = rf(ctx, token, patID, duration)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RetrievePAT provides a mock function with given fields: ctx, userID, patID
func (_m *PATS) RetrievePAT(ctx context.Context, userID string, patID string) (auth.PAT, error) {
	ret := _m.Called(ctx, userID, patID)

	if len(ret) == 0 {
		panic("no return value specified for RetrievePAT")
	}

	var r0 auth.PAT
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (auth.PAT, error)); ok {
		return rf(ctx, userID, patID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) auth.PAT); ok {
		r0 = rf(ctx, userID, patID)
	} else {
		r0 = ret.Get(0).(auth.PAT)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, userID, patID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RevokePATSecret provides a mock function with given fields: ctx, token, patID
func (_m *PATS) RevokePATSecret(ctx context.Context, token string, patID string) error {
	ret := _m.Called(ctx, token, patID)

	if len(ret) == 0 {
		panic("no return value specified for RevokePATSecret")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, token, patID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdatePATDescription provides a mock function with given fields: ctx, token, patID, description
func (_m *PATS) UpdatePATDescription(ctx context.Context, token string, patID string, description string) (auth.PAT, error) {
	ret := _m.Called(ctx, token, patID, description)

	if len(ret) == 0 {
		panic("no return value specified for UpdatePATDescription")
	}

	var r0 auth.PAT
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) (auth.PAT, error)); ok {
		return rf(ctx, token, patID, description)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) auth.PAT); ok {
		r0 = rf(ctx, token, patID, description)
	} else {
		r0 = ret.Get(0).(auth.PAT)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, token, patID, description)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdatePATName provides a mock function with given fields: ctx, token, patID, name
func (_m *PATS) UpdatePATName(ctx context.Context, token string, patID string, name string) (auth.PAT, error) {
	ret := _m.Called(ctx, token, patID, name)

	if len(ret) == 0 {
		panic("no return value specified for UpdatePATName")
	}

	var r0 auth.PAT
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) (auth.PAT, error)); ok {
		return rf(ctx, token, patID, name)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) auth.PAT); ok {
		r0 = rf(ctx, token, patID, name)
	} else {
		r0 = ret.Get(0).(auth.PAT)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, token, patID, name)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// NewPATS creates a new instance of PATS. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewPATS(t interface {
	mock.TestingT
	Cleanup(func())
}) *PATS {
	mock := &PATS{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
