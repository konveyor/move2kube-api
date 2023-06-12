/*
Copyright IBM Corporation 2023

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

package common

import (
	"net/http"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v3"
)

func TestDecodeJWT(t *testing.T) {
	tests := []struct {
		name        string
		jwt         string
		wantHeader  string
		wantPayload string
		wantErr     bool
	}{
		{
			name:        "Valid JWT",
			jwt:         "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantHeader:  `{"alg":"HS256","typ":"JWT"}`,
			wantPayload: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`,
			wantErr:     false,
		},
		{
			name:        "Invalid JWT - Incorrect number of parts",
			jwt:         "invalid.jwt",
			wantHeader:  "",
			wantPayload: "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotH, gotP, err := DecodeJWT(tt.jwt)

			if (err != nil) != tt.wantErr {
				t.Errorf("expected want error %+v, got error %+v. Error: %+v", tt.wantErr, (err == nil), err)
				return
			}

			if gotH != tt.wantHeader {
				t.Errorf("expected header%v, got %v", tt.wantHeader, gotH)
			}

			if gotP != tt.wantPayload {
				t.Errorf("expected payload %v, got %v", tt.wantPayload, gotP)
			}
		})
	}
}

func TestNormalizeName(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{
			input:    "HelloWorld",
			expected: "helloworld",
			wantErr:  false,
		},
		{
			input:    "Hello%World",
			expected: "hello-world",
			wantErr:  false,
		},
		{
			input:    "Hello$World$123",
			expected: "hello-world-123",
			wantErr:  false,
		},
		{
			input:    "   ",
			expected: "",
			wantErr:  true,
		},
	}

	for _, testCase := range testCases {
		actual, err := NormalizeName(testCase.input)

		if actual != testCase.expected {
			t.Errorf("Expected normalized name '%s' but got '%s'", testCase.expected, actual)
		}

		if (err == nil) && testCase.wantErr {
			t.Errorf("expected want error %+v, got error %+v. Error: %+v", testCase.wantErr, (err == nil), err)
		}

	}
}

func TestIsStringPresent(t *testing.T) {

	tests := []struct {
		name     string
		list     []string
		value    string
		expected bool
	}{
		{
			name:     "test if the list is empty",
			list:     []string{},
			value:    "move2kube",
			expected: false,
		},
		{
			name:     "test if the value is present in the list",
			list:     []string{"move2kube", "k8s", "kubernetes"},
			value:    "k8s",
			expected: true,
		},
		{
			name:     "test if the value is not present in the list",
			list:     []string{"move2kube", "k8s", "kubernetes"},
			value:    "k3s",
			expected: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IsStringPresent(test.list, test.value)
			if result != test.expected {
				t.Errorf("expected output for the input list %v and search value %q to be %v, but got %v", test.list, test.value, test.expected, result)
			}
		})
	}
}

func TestIsValidId(t *testing.T) {
	// Test cases
	tests := []struct {
		name     string
		id       string
		expected bool
	}{
		{
			name:     "Valid Id",
			id:       "abc123",
			expected: true,
		},
		{
			name:     "Valid Id with special characters",
			id:       "user-name_123",
			expected: true,
		},
		{
			name:     "Invalid Id with space",
			id:       "user name",
			expected: false,
		},
		{
			name:     "Invalid Id with unsupported characters",
			id:       "user@name",
			expected: false,
		},
	}

	// Run the tests
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := IsValidId(test.id)
			if result != test.expected {
				t.Errorf("expected output for input %q to be %v, but got %v", test.id, test.expected, result)
			}
		})
	}
}

func TestGetAccesTokenFromAuthzHeader(t *testing.T) {
	req := &http.Request{Header: make(http.Header)}
	token, err := GetAccesTokenFromAuthzHeader(req)
	wantedError := "the Authorization header is missing"
	if err == nil || err.Error() != wantedError {
		t.Errorf("Wanted error: %s, got: %v", wantedError, err)
	}
	if token != "" {
		t.Errorf("Wanted token to be empty, got: %s", token)
	}

	req = &http.Request{Header: make(http.Header)}
	authHeader := "invalid123"
	req.Header.Set("Authorization", authHeader)
	token, err = GetAccesTokenFromAuthzHeader(req)
	wantedError = "expected `Bearer <access token>` in the Authorization header. Actual: " + authHeader
	if err == nil || err.Error() != wantedError {
		t.Errorf("wanted error: %s, got: %v", wantedError, err)
	}
	if token != "" {
		t.Errorf("Wanted token to be empty, got: %s", token)
	}

	req = &http.Request{Header: make(http.Header)}
	token = "abc123"
	authHeader = "Bearer " + token
	req.Header.Set("Authorization", authHeader)
	token, err = GetAccesTokenFromAuthzHeader(req)
	wantedToken := token
	if err != nil {
		t.Errorf("Wanted no error, got: %v", err)
	}
	if token != wantedToken {
		t.Errorf("wanted token to be %s, got: %s", wantedToken, token)
	}
}

func TestDecodeToken(t *testing.T) {
	//  test if token is expired
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjIzNTM4NDM4fQ.TawqWVT0ZTR8iNH27PNQ9IJTtBSaK6lJL7uHVjneboU"
	JWebKey := "2fU0V1kpjj6A1K2oUsJTWsPdbmtVt1BGMhRQ6TqI2izDLuG3vIbxbuZMTR5vH4sjnN_kpYJHmlU_xumFPjAw7v3WRvFg2jFqf0"
	JJSONWebKey := jose.JSONWebKey{Key: JWebKey, KeyID: "mykey", Algorithm: "RSA"}
	_, err := DecodeToken(token, map[string]jose.JSONWebKey{"token": JJSONWebKey})
	wantedError := "the token expired"
	if err == nil || !strings.Contains(err.Error(), wantedError) {
		t.Errorf("failed to perform decode token for the token %+v, json web key %+v. Wanted Error : %+v, got Error : %+v", JWebKey, JJSONWebKey, wantedError, err)
	}
}
