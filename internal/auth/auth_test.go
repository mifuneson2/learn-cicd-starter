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
			name: "valid api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey 12345-abcde"},
			},
			expectedKey: "12345-abcde",
			expectedErr: nil,
		},
		{
			name: "valid api key with extra spaces",
			headers: http.Header{
				"Authorization": []string{"ApiKey 12345-abcde extra-data"},
			},
			expectedKey: "12345-abcde",
			expectedErr: nil,
		},
		{
			name:        "no authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "empty authorization header",
			headers: http.Header{
				"Authorization": []string{""},
			},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "missing api key",
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			expectedKey: "",
			expectedErr: nil,
		},
		{
			name: "wrong scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer 12345-abcde"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name: "incorrect casing for prefix",
			headers: http.Header{
				"Authorization": []string{"apikey 12345-abcde"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name: "no space separator",
			headers: http.Header{
				"Authorization": []string{"ApiKey12345-abcde"},
			},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualKey, actualErr := GetAPIKey(tc.headers)

			if actualKey != tc.expectedKey {
				t.Errorf("expected key %q, got %q", tc.expectedKey, actualKey)
			}

			if tc.expectedErr != nil {
				if actualErr == nil {
					t.Errorf("expected error %q, got nil", tc.expectedErr.Error())
				} else if actualErr.Error() != tc.expectedErr.Error() {
					t.Errorf("expected error %q, got %q", tc.expectedErr.Error(), actualErr.Error())
				}
			} else {
				if actualErr != nil {
					t.Errorf("expected no error, got %q", actualErr.Error())
				}
			}
		})
	}
}
