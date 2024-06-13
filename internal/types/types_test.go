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
package types

import (
	"testing"
)

func TestParseProjectInputType(t *testing.T) {
	tests := []struct {
		input    string
		expected ProjectInputType
		wantErr  bool
	}{
		{"sources", ProjectInputSources, false},
		{"customizations", ProjectInputCustomizations, false},
		{"configs", ProjectInputConfigs, false},
		{"reference", ProjectInputReference, false},
		{"invalidType", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := ParseProjectInputType(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseProjectInputType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result != tt.expected {
				t.Errorf("ParseProjectInputType() got = %v, want %v", result, tt.expected)
			}
		})
	}
}
