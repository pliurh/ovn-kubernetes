// Code generated by mockery v2.8.0. DO NOT EDIT.

package mocks

import (
	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	mock "github.com/stretchr/testify/mock"

	net "net"
)

// AddressSetFactory is an autogenerated mock type for the AddressSetFactory type
type AddressSetFactory struct {
	mock.Mock
}

// DestroyAddressSetInBackingStore provides a mock function with given fields: name
func (_m *AddressSetFactory) DestroyAddressSetInBackingStore(name string) error {
	ret := _m.Called(name)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(name)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// EnsureAddressSet provides a mock function with given fields: name
func (_m *AddressSetFactory) EnsureAddressSet(name string) error {
	ret := _m.Called(name)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(name)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewAddressSet provides a mock function with given fields: name, ips
func (_m *AddressSetFactory) NewAddressSet(name string, ips []net.IP) (addressset.AddressSet, error) {
	ret := _m.Called(name, ips)

	var r0 addressset.AddressSet
	if rf, ok := ret.Get(0).(func(string, []net.IP) addressset.AddressSet); ok {
		r0 = rf(name, ips)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(addressset.AddressSet)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, []net.IP) error); ok {
		r1 = rf(name, ips)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// ProcessEachAddressSet provides a mock function with given fields: iteratorFn
func (_m *AddressSetFactory) ProcessEachAddressSet(iteratorFn addressset.AddressSetIterFunc) error {
	ret := _m.Called(iteratorFn)

	var r0 error
	if rf, ok := ret.Get(0).(func(addressset.AddressSetIterFunc) error); ok {
		r0 = rf(iteratorFn)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
