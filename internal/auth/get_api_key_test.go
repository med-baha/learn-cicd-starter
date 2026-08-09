package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers     http.Header
		expectedKey string
		expectedErr string
	}{
		"no authorization header": {
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded.Error(),
		},
		"valid api key": {
			headers:     http.Header{"Authorization": []string{"ApiKey 12345"}},
			expectedKey: "12345",
			expectedErr: "",
		},
		"malformed no space": {
			headers:     http.Header{"Authorization": []string{"ApiKey12345"}},
			expectedKey: "",
			expectedErr: "malformed authorization header",
		},
		"malformed wrong scheme": {
			headers:     http.Header{"Authorization": []string{"Bearer 12345"}},
			expectedKey: "",
			expectedErr: "malformed authorization header",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)
			if key != tc.expectedKey {
				t.Errorf("expected key %q, got %q", tc.expectedKey, key)
			}
			if tc.expectedErr == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				return
			}
			if err == nil || err.Error() != tc.expectedErr {
				t.Errorf("expected error %q, got %v", tc.expectedErr, err)
			}
		})
	}
}
