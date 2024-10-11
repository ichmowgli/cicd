package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "Valid API Key",
			headers:     http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectedKey: "my-secret-key",
			expectedErr: nil,
		},
		{
			name:        "No Authorization Header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed Authorization Header - Wrong Scheme",
			headers:     http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "Malformed Authorization Header - No Key",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "Multiple Authorization Headers",
			headers:     http.Header{"Authorization": []string{"ApiKey first-key", "ApiKey second-key"}},
			expectedKey: "first-key", // The first one is taken
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			if gotKey != tt.expectedKey || (gotErr != nil && gotErr.Error() != tt.expectedErr.Error()) {
				t.Errorf("GetAPIKey() = %v, %v; want %v, %v", gotKey, gotErr, tt.expectedKey, tt.expectedErr)
			}
		})
	}
}
