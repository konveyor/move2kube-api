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
