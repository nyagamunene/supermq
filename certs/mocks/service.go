// Code generated by mockery v2.43.2. DO NOT EDIT.

// Copyright (c) Abstract Machines

package mocks

import (
	context "context"

	certs "github.com/absmach/magistrala/certs"

	mock "github.com/stretchr/testify/mock"
)

// Service is an autogenerated mock type for the Service type
type Service struct {
	mock.Mock
}

// IssueCert provides a mock function with given fields: ctx, token, thingID, ttl
func (_m *Service) IssueCert(ctx context.Context, token string, thingID string, ttl string) (certs.Cert, error) {
	ret := _m.Called(ctx, token, thingID, ttl)

	if len(ret) == 0 {
		panic("no return value specified for IssueCert")
	}

	var r0 certs.Cert
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) (certs.Cert, error)); ok {
		return rf(ctx, token, thingID, ttl)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, string) certs.Cert); ok {
		r0 = rf(ctx, token, thingID, ttl)
	} else {
		r0 = ret.Get(0).(certs.Cert)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, string) error); ok {
		r1 = rf(ctx, token, thingID, ttl)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListCerts provides a mock function with given fields: ctx, token, thingID, pm
func (_m *Service) ListCerts(ctx context.Context, token string, thingID string, pm certs.PageMetadata) (certs.CertPage, error) {
	ret := _m.Called(ctx, token, thingID, pm)

	if len(ret) == 0 {
		panic("no return value specified for ListCerts")
	}

	var r0 certs.CertPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, certs.PageMetadata) (certs.CertPage, error)); ok {
		return rf(ctx, token, thingID, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, certs.PageMetadata) certs.CertPage); ok {
		r0 = rf(ctx, token, thingID, pm)
	} else {
		r0 = ret.Get(0).(certs.CertPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, certs.PageMetadata) error); ok {
		r1 = rf(ctx, token, thingID, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ListSerials provides a mock function with given fields: ctx, token, thingID, pm
func (_m *Service) ListSerials(ctx context.Context, token string, thingID string, pm certs.PageMetadata) (certs.CertPage, error) {
	ret := _m.Called(ctx, token, thingID, pm)

	if len(ret) == 0 {
		panic("no return value specified for ListSerials")
	}

	var r0 certs.CertPage
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string, certs.PageMetadata) (certs.CertPage, error)); ok {
		return rf(ctx, token, thingID, pm)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string, certs.PageMetadata) certs.CertPage); ok {
		r0 = rf(ctx, token, thingID, pm)
	} else {
		r0 = ret.Get(0).(certs.CertPage)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string, certs.PageMetadata) error); ok {
		r1 = rf(ctx, token, thingID, pm)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RevokeCert provides a mock function with given fields: ctx, token, thingID
func (_m *Service) RevokeCert(ctx context.Context, token string, thingID string) (certs.Revoke, error) {
	ret := _m.Called(ctx, token, thingID)

	if len(ret) == 0 {
		panic("no return value specified for RevokeCert")
	}

	var r0 certs.Revoke
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (certs.Revoke, error)); ok {
		return rf(ctx, token, thingID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) certs.Revoke); ok {
		r0 = rf(ctx, token, thingID)
	} else {
		r0 = ret.Get(0).(certs.Revoke)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, token, thingID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ViewCert provides a mock function with given fields: ctx, token, serialID
func (_m *Service) ViewCert(ctx context.Context, token string, serialID string) (certs.Cert, error) {
	ret := _m.Called(ctx, token, serialID)

	if len(ret) == 0 {
		panic("no return value specified for ViewCert")
	}

	var r0 certs.Cert
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, string) (certs.Cert, error)); ok {
		return rf(ctx, token, serialID)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, string) certs.Cert); ok {
		r0 = rf(ctx, token, serialID)
	} else {
		r0 = ret.Get(0).(certs.Cert)
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, token, serialID)
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
