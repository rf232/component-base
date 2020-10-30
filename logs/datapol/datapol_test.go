/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package datapol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

type withDatapolTag struct {
	Key string `json:"key" datapolicy:"password"`
}

type withExternalType struct {
	Token jwt.JSONWebToken `json:"jwt"`
}

type noDatapol struct {
	Key string `json:"key"`
}

type datapolInMember struct {
	secrets withDatapolTag
}

type datapolInSlice struct {
	secrets []withDatapolTag
}

type datapolInMap struct {
	secrets map[string]withDatapolTag
}

type datapolBehindPointer struct {
	secrets *withDatapolTag
}

func TestValidate(t *testing.T) {
	testcases := []struct {
		name   string
		value  interface{}
		expect []string
	}{{
		name:   "Empty password",
		value:  withDatapolTag{},
		expect: []string{},
	}, {
		name: "Non-empty password",
		value: withDatapolTag{
			Key: "hunter2",
		},
		expect: []string{"password"},
	}, {
		name:   "empty external type",
		value:  withExternalType{Token: jwt.JSONWebToken{}},
		expect: []string{},
	}, {
		name: "external type",
		value: withExternalType{Token: jwt.JSONWebToken{
			Headers: []jose.Header{{KeyID: "hunter2"}},
		}},
		expect: []string{"token"},
	}, {
		name:   "no datapol tag",
		value:  noDatapol{Key: "hunter2"},
		expect: []string{},
	}, {
		name: "nested",
		value: datapolInMember{
			secrets: withDatapolTag{
				Key: "hunter2",
			},
		},
		expect: []string{"password"},
	}, {
		name: "nested in pointer",
		value: datapolBehindPointer{
			secrets: &withDatapolTag{Key: "hunter2"},
		},
		expect: []string{},
	}, {
		name: "nested in slice",
		value: datapolInSlice{
			secrets: []withDatapolTag{{Key: "hunter2"}},
		},
		expect: []string{"password"},
	}, {
		name: "nested in map",
		value: datapolInMap{
			secrets: map[string]withDatapolTag{
				"key": withDatapolTag{Key: "hunter2"},
			},
		},
		expect: []string{"password"},
	}, {
		name: "nested in map but empty",
		value: datapolInMap{
			secrets: map[string]withDatapolTag{
				"key": withDatapolTag{},
			},
		},
		expect: []string{},
	}}
	for _, tc := range testcases {
		res := Verify(tc.value)
		if !assert.ElementsMatch(t, tc.expect, res) {
			t.Errorf("Wrong set of tags for %q. expect %v, got %v", tc.name, tc.expect, res)
		}
	}
}
