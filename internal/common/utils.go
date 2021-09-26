/*
Copyright IBM Corporation 2021

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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/konveyor/move2kube-api/internal/types"
	"github.com/sirupsen/logrus"
)

// DecodeJWT decodes the JSON web token and returns the payload
func DecodeJWT(jwt string) (header string, payload string, err error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return "", "", fmt.Errorf("expected there to be 3 parts. actual len %d . actual: %s", len(parts), jwt)
	}
	for i, part := range parts[:2] {
		x, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return "", "", err
		}
		parts[i] = string(x)
	}
	return parts[0], parts[1], nil
}

// DecodeToken verifies the signatures on a JWS access token and also decodes and returns the payload.
// It will return an error if the signature verification fails or if the token has expired.
func DecodeToken(token string, jwks map[string]jose.JSONWebKey) ([]byte, error) {
	jws, err := jose.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse the token %s as a JWS. Error: %q", token, err)
	}
	unverifiable := false
	var unverifiableDecoded []byte
	for i, sig := range jws.Signatures {
		if jose.SignatureAlgorithm(sig.Header.Algorithm) == jose.HS256 {
			// refresh tokens use a symmetric algorithm such as HS256 (HMAC with SHA256)
			// https://keycloak.discourse.group/t/rs256-for-refresh-tokens/6849
			unverifiable = true
			logrus.Debugf("the signature %+v was created using a symmetric algorithm and is not meant to be verified", sig)
			_, decoded, err := DecodeJWT(token)
			if err != nil {
				logrus.Debugf("failed to decode the token %s as a JWT. Error: %q", token, err)
				continue
			}
			decodeToken := struct{ Exp int64 }{}
			if err := json.Unmarshal([]byte(decoded), &decodeToken); err != nil {
				logrus.Debugf("failed to unmarshal the decoded payload %s as a token. Error: %q", string(decoded), err)
				continue
			}
			if decodeToken.Exp <= time.Now().Unix() {
				return []byte(decoded), types.ErrorTokenExpired{Exp: decodeToken.Exp}
			}
			unverifiableDecoded = []byte(decoded)
			continue
		}
		kid := sig.Header.KeyID
		jwk, ok := jwks[kid]
		if !ok {
			logrus.Debugf("the key id %s used to sign the jwk is missing from the provided jwks %+v", kid, jwks)
			continue
		}
		verifiedSigIdx, _, decoded, err := jws.VerifyMulti(jwk)
		if err != nil {
			logrus.Debugf("failed to verify the signature %+v using the key %+v . Error: %q", sig, jwk, err)
			continue
		}
		if i != verifiedSigIdx {
			logrus.Debugf("the index of the signature that was verified is %d but the key %+v was supposed to verify signature at index %d", verifiedSigIdx, jwk, i)
			continue
		}
		decodeToken := struct{ Exp int64 }{}
		if err := json.Unmarshal(decoded, &decodeToken); err != nil {
			return decoded, fmt.Errorf("failed to unmarshal the decoded payload %s as a token. Error: %q", string(decoded), err)
		}
		if decodeToken.Exp <= time.Now().Unix() {
			return decoded, types.ErrorTokenExpired{Exp: decodeToken.Exp}
		}
		return decoded, nil
	}
	if unverifiable {
		return unverifiableDecoded, types.ErrorTokenUnverifiable{}
	}
	return nil, fmt.Errorf("failed to verify the token %s using the JWKs %+v . Error: %q", token, jwks, err)
}

// GetAccesTokenFromAuthzHeader returns the access token from the authorization bearer HTTP header
func GetAccesTokenFromAuthzHeader(r *http.Request) (string, error) {
	authzHeader := r.Header.Get(AUTHZ_HEADER)
	if authzHeader == "" {
		return "", fmt.Errorf("the Authorization header is missing")
	}
	if !strings.HasPrefix(authzHeader, "Bearer ") {
		return "", fmt.Errorf("expected `Bearer <access token>` in the Authorization header. Actual: %s", authzHeader)
	}
	return strings.TrimPrefix(authzHeader, "Bearer "), nil
}

// IsValidId returns true if the provided Id is valid
func IsValidId(id string) bool {
	return ID_REGEXP.MatchString(id)
}

// IsStringPresent checks if a value is present in a slice
func IsStringPresent(list []string, value string) bool {
	for _, val := range list {
		if strings.EqualFold(val, value) {
			return true
		}
	}
	return false
}

// NormalizeName normalizes the name
func NormalizeName(name string) (string, error) {
	normalizedName := strings.ToLower(name)
	normalizedName = strings.Trim(INVALID_NAME_CHARS_REGEXP.ReplaceAllLiteralString(normalizedName, "-"), "-")
	if len(normalizedName) == 0 {
		return "", fmt.Errorf("after normalization the name '%s' turns into the empty string", name)
	}
	return normalizedName, nil
}

// GetTimestamp returns the current time in RFC 3339 (ISO 8601) standard format
func GetTimestamp() (string, int64, error) {
	now := time.Now().UTC()
	timeBytes, err := now.MarshalText()
	if err != nil {
		return string(timeBytes), now.Unix(), fmt.Errorf("failed to get the current time in RFC 3339 (ISO 8601) standard format. Error: %q", err)
	}
	return string(timeBytes), now.Unix(), nil
}
