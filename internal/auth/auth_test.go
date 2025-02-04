package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		want      string
		expectErr error
	}{
		{
			name:      "No Authorization Header",
			headers:   http.Header{},
			want:      "",
			expectErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header",
			headers: http.Header{
				"Authorization": []string{"Bearer token"},
			},
			want:      "",
			expectErr: errors.New("malformed authorization header"),
		},
		{
			name: "Correct Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey correctapikey"},
			},
			want:      "correctapikey",
			expectErr: nil,
		},
		{
			name: "Empty API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey "},
			},
			want:      "",
			expectErr: errors.New("malformed authorization header"),
		},
		{
			name: "Multiple Authorization Headers",
			headers: http.Header{
				"Authorization": []string{"ApiKey firstkey", "ApiKey secondkey"},
			},
			want:      "firstkey",
			expectErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)
			if got != tt.want || (err != nil && err.Error() != tt.expectErr.Error()) {
				t.Errorf("GetAPIKey() = %v, %v; want %v, %v", got, err, tt.want, tt.expectErr)
			}
		})
	}
}
