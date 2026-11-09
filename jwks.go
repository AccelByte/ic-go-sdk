// Copyright 2023 AccelByte Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ic

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/AccelByte/ic-go-sdk/internal/tracing"
	"github.com/cenkalti/backoff"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
)

var jwtEncoding = base64.URLEncoding.WithPadding(base64.NoPadding)

const (
	// keyTypeRSA is the JWK "kty" value of the RSA keys IAM signs tokens with.
	keyTypeRSA = "RSA"
	// keyUseSignature is the JWK "use" value of a signing key.
	keyUseSignature = "sig"

	// The exponent limits crypto/rsa applies when verifying a signature.
	minRSAExponent = 3
	maxRSAExponent = 1<<31 - 1
)

// JWK contains json web key's data
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// Keys contains json web keys
type Keys struct {
	Keys []JWK `json:"keys"`
}

// nolint: funlen
func (client *DefaultClient) getJWKS(opts ...Option) (map[string]*rsa.PublicKey, error) {
	options := processOptions(opts)
	span, _ := tracing.StartSpanFromContext(options.traceCtx, "client.getJWKS")

	defer tracing.Finish(span)

	req, err := http.NewRequest("GET", client.config.BaseURL+jwksPath, nil)
	if err != nil {
		tracing.TraceError(span, errors.Wrap(err, "getJWKS: unable to create new JWKS request"))
		return nil, errors.Wrap(err, "getJWKS: unable to create new JWKS request")
	}

	req.SetBasicAuth(client.config.ClientID, client.config.ClientSecret)

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	var responseStatusCode int

	var responseBodyBytes []byte

	// nolint: dupl
	err = backoff.
		Retry(
			func() error {
				var e error

				reqSpan := tracing.StartChildSpan(span, "HTTP Request: "+req.Method+" "+req.URL.Path)
				defer tracing.Finish(reqSpan)
				jErr := tracing.InjectSpanIntoRequest(reqSpan, req)
				if jErr != nil {
					logrus.Warn(jErr)
				}

				resp, e := client.httpClient.Do(req)
				if e != nil {
					return backoff.Permanent(e)
				}
				defer resp.Body.Close()

				responseStatusCode = resp.StatusCode
				if resp.StatusCode >= http.StatusInternalServerError {
					tracing.TraceError(reqSpan, fmt.Errorf("StatusCode: %v", resp.StatusCode))
					return errors.Errorf("getJWKS: endpoint returned status code : %v", responseStatusCode)
				}

				responseBodyBytes, e = ioutil.ReadAll(resp.Body)
				if e != nil {
					tracing.TraceError(reqSpan, fmt.Errorf("Body.ReadAll: %s", e))
					return errors.Wrap(e, "getJWKS: unable to read response body")
				}

				return nil
			},
			b,
		)

	if err != nil {
		tracing.TraceError(span, errors.Wrap(err, "getJWKS: unable to do HTTP request to get JWKS"))
		return nil, errors.Wrap(err, "getJWKS: unable to do HTTP request to get JWKS")
	}

	if responseStatusCode != http.StatusOK {
		tracing.TraceError(span, errors.Errorf("getJWKS: unable to get JWKS: error code : %d, error message : %s",
			responseStatusCode, string(responseBodyBytes)))

		return nil, errors.Errorf("getJWKS: unable to get JWKS: error code : %d, error message : %s",
			responseStatusCode, string(responseBodyBytes))
	}

	var jwks Keys

	err = json.Unmarshal(responseBodyBytes, &jwks)
	if err != nil {
		tracing.TraceError(span, errors.Wrap(err, "getJWKS: unable to unmarshal response body"))
		return nil, errors.Wrap(err, "getJWKS: unable to unmarshal response body")
	}
	keys := make(map[string]*rsa.PublicKey)
	for i := range jwks.Keys {
		jwk := &jwks.Keys[i]

		// A JWKS can legitimately hold other keys, so skipping them is only a debug log.
		if !isRSASigningKey(jwk) {
			log(fmt.Sprintf("getJWKS: skipping key %q with key type %q and use %q", jwk.Kid, jwk.Kty, jwk.Use))

			continue
		}

		key, errGenerate := generatePublicKey(jwk)
		if errGenerate != nil {
			skipKey(span, fmt.Sprintf("getJWKS: skipping key %q: %v", jwk.Kid, errGenerate))

			continue
		}
		keys[jwk.Kid] = key
	}
	return keys, nil
}

// isRSASigningKey reports whether jwk is an RSA key that may be used to verify
// signatures. A missing kty or use is accepted, and the comparison ignores case.
// Keys of another type or use were loaded before if their n and e happened to
// parse, but couldn't verify an RS256 signature as an RSA signing key.
func isRSASigningKey(jwk *JWK) bool {
	return (jwk.Kty == "" || strings.EqualFold(jwk.Kty, keyTypeRSA)) &&
		(jwk.Use == "" || strings.EqualFold(jwk.Use, keyUseSignature))
}

// skipKey reports an RSA signing key that is malformed. The other keys still
// load, so this is a warning and a span log, not a span error.
func skipKey(span opentracing.Span, msg string) {
	logrus.Warn("[IC-Go-SDK] " + msg)
	tracing.AddLog(span, "message", msg)
}

func (client *DefaultClient) getPublicKey(keyID string) (*rsa.PublicKey, error) {
	keys, err := client.GetKeys()
	if err != nil {
		return nil, err
	}
	key, ok := keys[keyID]
	if !ok {
		return nil, errors.New("getPublicKey: public key doesn't exist")
	}

	return key, nil
}

// generatePublicKey builds the RSA public key described by jwk. It rejects keys
// crypto/rsa refuses whatever its settings, so such a key is never used. The
// minimum key size isn't checked here.
func generatePublicKey(jwk *JWK) (*rsa.PublicKey, error) {
	n, err := getModulus(jwk.N)
	if err != nil {
		return nil, err
	}

	// The minimum key size is left to crypto/rsa, which can be changed at run time
	// (GODEBUG rsa1024min). A modulus that isn't odd and greater than 1 is never valid.
	if n.Cmp(big.NewInt(1)) <= 0 || n.Bit(0) == 0 {
		return nil, errors.New("generatePublicKey: JWK modulus isn't an odd number greater than 1")
	}

	e, err := getPublicExponent(jwk.E)
	if err != nil {
		return nil, err
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func getModulus(jwkN string) (*big.Int, error) {
	decodedN, err := jwtEncoding.DecodeString(jwkN)
	if err != nil {
		return nil, errors.Wrap(err, "getModulus: unable to decode JWK modulus string")
	}

	return new(big.Int).SetBytes(decodedN), nil
}

// getPublicExponent decodes a JWK exponent. Like crypto/rsa, it accepts only an
// odd exponent from 3 to 2^31-1.
func getPublicExponent(jwkE string) (int, error) {
	decodedE, err := jwtEncoding.DecodeString(jwkE)
	if err != nil {
		return 0, errors.Wrap(err, "getPublicExponent: unable to decode JWK exponent string")
	}

	// maxRSAExponent fits in 4 bytes.
	decodedE = bytes.TrimLeft(decodedE, "\x00")
	if len(decodedE) == 0 || len(decodedE) > 4 {
		return 0, errors.Errorf("getPublicExponent: JWK exponent is %d significant bytes, want 1 to 4", len(decodedE))
	}

	var e uint64
	for _, b := range decodedE {
		e = e<<8 | uint64(b)
	}

	if e < minRSAExponent || e > maxRSAExponent || e%2 == 0 {
		return 0, errors.Errorf("getPublicExponent: JWK exponent %d isn't an odd number from %d to %d", e, minRSAExponent, maxRSAExponent)
	}

	return int(e), nil
}
