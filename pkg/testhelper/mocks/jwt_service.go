// Code generated by mockery v0.0.0-dev. DO NOT EDIT.

package mocks

import mock "github.com/stretchr/testify/mock"

// JWTService is an autogenerated mock type for the JWTService type
type JWTService struct {
	mock.Mock
}

// GenerateToken provides a mock function with given fields: username
func (_m *JWTService) GenerateToken(username string) (string, error) {
	ret := _m.Called(username)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(username)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(username)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ValidateToken provides a mock function with given fields: token
func (_m *JWTService) ValidateToken(token string) (string, error) {
	ret := _m.Called(token)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(token)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
