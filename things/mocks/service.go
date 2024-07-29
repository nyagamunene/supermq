// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	clients "github.com/absmach/magistrala/pkg/clients"

	magistrala "github.com/absmach/magistrala"

	mock "github.com/stretchr/testify/mock"
)

// Service is an autogenerated mock type for the Service type
type Service struct {
	mock.Mock
}

// Authorize provides a mock function with given fields: ctx, req
func (_m *Service) Authorize(ctx context.Context, req *magistrala.AuthorizeReq) (string, error) {
	ret := _m.Called(ctx, req)

	if len(ret) == 0 {
		panic("no return value specified for Authorize")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *magistrala.AuthorizeReq) (string, error)); ok {
		return rf(ctx, req)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *magistrala.AuthorizeReq) string); ok {
		r0 = rf(ctx, req)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, *magistrala.AuthorizeReq) error); ok {
		r1 = rf(ctx, req)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CreateThings provides a mock function with given fields: ctx, token, client
func (_m *Service) CreateThings(ctx context.Context, token string, client ...clients.Client) ([]clients.Client, error) {
	_va := make([]interface{}, len(client))
	for _i := range client {
		_va[_i] = client[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, token)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for CreateThings")
	}

	var r0 []clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, ...clients.Client) ([]clients.Client, error)); ok {
		return rf(ctx, token, client...)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, ...clients.Client) []clients.Client); ok {
		r0 = rf(ctx, token, client...)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]clients.Client)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, ...clients.Client) error); ok {
		r1 = rf(ctx, token, client...)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeleteClient provides a mock function with given fields: ctx, token, id
func (_m *Service) DeleteClient(ctx context.Context, token string, id string) error {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for DeleteClient")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) error); ok {
		r0 = rf(ctx, token, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DisableClient provides a mock function with given fields: ctx, token, id
func (_m *Service) DisableClient(ctx context.Context, token string, id string) (clients.Client, error) {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for DisableClient")
	}

	var r0 clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (clients.Client, error)); ok {
		return rf(ctx, token, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) clients.Client); ok {
		r0 = rf(ctx, token, id)
	} else {
		r0 = ret.Get(0).(clients.Client)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, token, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// EnableClient provides a mock function with given fields: ctx, token, id
func (_m *Service) EnableClient(ctx context.Context, token string, id string) (clients.Client, error) {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for EnableClient")
	}

	var r0 clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (clients.Client, error)); ok {
		return rf(ctx, token, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) clients.Client); ok {
		r0 = rf(ctx, token, id)
	} else {
		r0 = ret.Get(0).(clients.Client)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, token, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Identify provides a mock function with given fields: ctx, key
func (_m *Service) Identify(ctx context.Context, key string) (string, error) {
	ret := _m.Called(ctx, key)

	if len(ret) == 0 {
		panic("no return value specified for Identify")
	}

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (string, error)); ok {
		return rf(ctx, key)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) string); ok {
		r0 = rf(ctx, key)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListClients provides a mock function with given fields: ctx, token, reqUserID, pm
func (_m *Service) ListClients(ctx context.Context, token string, reqUserID string, pm clients.Page) (clients.ClientsPage, error) {
	ret := _m.Called(ctx, token, reqUserID, pm)

	if len(ret) == 0 {
		panic("no return value specified for ListClients")
	}

	var r0 clients.ClientsPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, clients.Page) (clients.ClientsPage, error)); ok {
		return rf(ctx, token, reqUserID, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, clients.Page) clients.ClientsPage); ok {
		r0 = rf(ctx, token, reqUserID, pm)
	} else {
		r0 = ret.Get(0).(clients.ClientsPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, clients.Page) error); ok {
		r1 = rf(ctx, token, reqUserID, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListClientsByGroup provides a mock function with given fields: ctx, token, groupID, pm
func (_m *Service) ListClientsByGroup(ctx context.Context, token string, groupID string, pm clients.Page) (clients.MembersPage, error) {
	ret := _m.Called(ctx, token, groupID, pm)

	if len(ret) == 0 {
		panic("no return value specified for ListClientsByGroup")
	}

	var r0 clients.MembersPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, clients.Page) (clients.MembersPage, error)); ok {
		return rf(ctx, token, groupID, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, clients.Page) clients.MembersPage); ok {
		r0 = rf(ctx, token, groupID, pm)
	} else {
		r0 = ret.Get(0).(clients.MembersPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, clients.Page) error); ok {
		r1 = rf(ctx, token, groupID, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Share provides a mock function with given fields: ctx, token, id, relation, userids
func (_m *Service) Share(ctx context.Context, token string, id string, relation string, userids ...string) error {
	_va := make([]interface{}, len(userids))
	for _i := range userids {
		_va[_i] = userids[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, token, id, relation)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Share")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, ...string) error); ok {
		r0 = rf(ctx, token, id, relation, userids...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// Unshare provides a mock function with given fields: ctx, token, id, relation, userids
func (_m *Service) Unshare(ctx context.Context, token string, id string, relation string, userids ...string) error {
	_va := make([]interface{}, len(userids))
	for _i := range userids {
		_va[_i] = userids[_i]
	}
	var _ca []interface{}
	_ca = append(_ca, ctx, token, id, relation)
	_ca = append(_ca, _va...)
	ret := _m.Called(_ca...)

	if len(ret) == 0 {
		panic("no return value specified for Unshare")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string, ...string) error); ok {
		r0 = rf(ctx, token, id, relation, userids...)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateClient provides a mock function with given fields: ctx, token, client
func (_m *Service) UpdateClient(ctx context.Context, token string, client clients.Client) (clients.Client, error) {
	ret := _m.Called(ctx, token, client)

	if len(ret) == 0 {
		panic("no return value specified for UpdateClient")
	}

	var r0 clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, clients.Client) (clients.Client, error)); ok {
		return rf(ctx, token, client)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, clients.Client) clients.Client); ok {
		r0 = rf(ctx, token, client)
	} else {
		r0 = ret.Get(0).(clients.Client)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, clients.Client) error); ok {
		r1 = rf(ctx, token, client)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateClientSecret provides a mock function with given fields: ctx, token, id, key
func (_m *Service) UpdateClientSecret(ctx context.Context, token string, id string, key string) (clients.Client, error) {
	ret := _m.Called(ctx, token, id, key)

	if len(ret) == 0 {
		panic("no return value specified for UpdateClientSecret")
	}

	var r0 clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) (clients.Client, error)); ok {
		return rf(ctx, token, id, key)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) clients.Client); ok {
		r0 = rf(ctx, token, id, key)
	} else {
		r0 = ret.Get(0).(clients.Client)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, token, id, key)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateClientTags provides a mock function with given fields: ctx, token, client
func (_m *Service) UpdateClientTags(ctx context.Context, token string, client clients.Client) (clients.Client, error) {
	ret := _m.Called(ctx, token, client)

	if len(ret) == 0 {
		panic("no return value specified for UpdateClientTags")
	}

	var r0 clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, clients.Client) (clients.Client, error)); ok {
		return rf(ctx, token, client)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, clients.Client) clients.Client); ok {
		r0 = rf(ctx, token, client)
	} else {
		r0 = ret.Get(0).(clients.Client)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, clients.Client) error); ok {
		r1 = rf(ctx, token, client)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// VerifyConnections provides a mock function with given fields: ctx, token, thingID, groupID
func (_m *Service) VerifyConnections(ctx context.Context, token string, thingID []string, groupID []string) (clients.ConnectionsPage, error) {
	ret := _m.Called(ctx, token, thingID, groupID)

	if len(ret) == 0 {
		panic("no return value specified for VerifyConnections")
	}

	var r0 clients.ConnectionsPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, []string, []string) (clients.ConnectionsPage, error)); ok {
		return rf(ctx, token, thingID, groupID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, []string, []string) clients.ConnectionsPage); ok {
		r0 = rf(ctx, token, thingID, groupID)
	} else {
		r0 = ret.Get(0).(clients.ConnectionsPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, []string, []string) error); ok {
		r1 = rf(ctx, token, thingID, groupID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ViewClient provides a mock function with given fields: ctx, token, id
func (_m *Service) ViewClient(ctx context.Context, token string, id string) (clients.Client, error) {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for ViewClient")
	}

	var r0 clients.Client
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (clients.Client, error)); ok {
		return rf(ctx, token, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) clients.Client); ok {
		r0 = rf(ctx, token, id)
	} else {
		r0 = ret.Get(0).(clients.Client)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, token, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ViewClientPerms provides a mock function with given fields: ctx, token, id
func (_m *Service) ViewClientPerms(ctx context.Context, token string, id string) ([]string, error) {
	ret := _m.Called(ctx, token, id)

	if len(ret) == 0 {
		panic("no return value specified for ViewClientPerms")
	}

	var r0 []string
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) ([]string, error)); ok {
		return rf(ctx, token, id)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) []string); ok {
		r0 = rf(ctx, token, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]string)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, token, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
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
