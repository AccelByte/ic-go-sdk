// Copyright 2026 AccelByte Inc
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
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	testKeyOnce sync.Once
	testKey     *rsa.PublicKey
	errTestKey  error
)

func testPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()

	testKeyOnce.Do(func() {
		var privateKey *rsa.PrivateKey

		privateKey, errTestKey = rsa.GenerateKey(rand.Reader, 2048)
		if errTestKey == nil {
			testKey = &privateKey.PublicKey
		}
	})
	require.NoError(t, errTestKey)

	return testKey
}

func testRSAJWK(t *testing.T, kid string) JWK {
	t.Helper()

	return JWK{
		Kty: keyTypeRSA,
		Use: keyUseSignature,
		Kid: kid,
		N:   jwtEncoding.EncodeToString(testPublicKey(t).N.Bytes()),
		E:   "AQAB",
	}
}

func encodeExponent(b ...byte) string { return jwtEncoding.EncodeToString(b) }

// newJWKSClient returns a client whose JWKS endpoint serves keys.
func newJWKSClient(t *testing.T, keys []JWK) *DefaultClient {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, jwksPath, r.URL.Path)
		assert.NoError(t, json.NewEncoder(w).Encode(Keys{Keys: keys}))
	}))
	t.Cleanup(server.Close)

	return NewDefaultClient(&Config{BaseURL: server.URL})
}

func assertKeys(t *testing.T, keys map[string]*rsa.PublicKey, want ...string) {
	t.Helper()

	got := make([]string, 0, len(keys))
	for kid, key := range keys {
		got = append(got, kid)

		assert.Equal(t, 0, testPublicKey(t).N.Cmp(key.N), "key %q modulus", kid)
		assert.Equal(t, testPublicKey(t).E, key.E, "key %q exponent", kid)
	}

	assert.ElementsMatch(t, want, got)
}

// A key that can't be parsed must not stop the other keys from loading. Before,
// getJWKS returned no keys and no error, so every token failed validation.
func Test_GetJWKSSkipsUnparsableKey(t *testing.T) {
	t.Parallel()

	badKey := JWK{Kty: keyTypeRSA, Kid: "bad", N: "not base64url!", E: "AQAB"}

	client := newJWKSClient(t, []JWK{badKey, testRSAJWK(t, "good")})

	keys, err := client.getJWKS()
	require.NoError(t, err)
	assertKeys(t, keys, "good")

	// The cached path that token validation uses returns the same keys.
	keys, err = client.GetKeys()
	require.NoError(t, err)
	assertKeys(t, keys, "good")
}

// Keys crypto/rsa refuses whatever its settings are skipped.
func Test_GetJWKSSkipsKeysRSACannotVerifyWith(t *testing.T) {
	t.Parallel()

	withExponent := func(kid, e string) JWK {
		jwk := testRSAJWK(t, kid)
		jwk.E = e

		return jwk
	}
	withModulus := func(kid string, n *big.Int) JWK {
		jwk := testRSAJWK(t, kid)
		jwk.N = jwtEncoding.EncodeToString(n.Bytes())

		return jwk
	}
	evenModulus := new(big.Int).SetBit(new(big.Int).Set(testPublicKey(t).N), 0, 0)
	encryptionKey := testRSAJWK(t, "enc")
	encryptionKey.Use = "enc"

	client := newJWKSClient(t, []JWK{
		withExponent("zero-exponent", encodeExponent(0)),
		withExponent("empty-exponent", ""),
		withExponent("exponent-one", encodeExponent(1)),
		withExponent("even-exponent", encodeExponent(4)),
		withExponent("exponent-too-large", encodeExponent(0x80, 0, 0, 1)),
		withExponent("exponent-too-long", encodeExponent(1, 0, 0, 0, 0, 0, 0, 0, 1)),
		withModulus("zero-modulus", big.NewInt(0)),
		withModulus("one-modulus", big.NewInt(1)),
		withModulus("even-modulus", evenModulus),
		{Kty: "EC", Kid: "ec"},
		encryptionKey,
		testRSAJWK(t, "good"),
	})

	keys, err := client.getJWKS()
	require.NoError(t, err)
	assertKeys(t, keys, "good")
}

// kty and use are compared without case, as keys in any case were trusted before.
func Test_GetJWKSAcceptsKeyTypeAndUseInAnyCase(t *testing.T) {
	t.Parallel()

	upper := testRSAJWK(t, "upper")
	upper.Use = "SIG"
	lower := testRSAJWK(t, "lower")
	lower.Kty = "rsa"
	bare := testRSAJWK(t, "bare")
	bare.Kty, bare.Use = "", ""

	keys, err := newJWKSClient(t, []JWK{upper, lower, bare}).getJWKS()
	require.NoError(t, err)
	assertKeys(t, keys, "upper", "lower", "bare")
}

func Test_GetJWKSWithEmptyKeyList(t *testing.T) {
	t.Parallel()

	keys, err := newJWKSClient(t, nil).getJWKS()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func Test_GetPublicExponent(t *testing.T) {
	t.Parallel()

	valid := map[string]int{
		"AQAB":                                 65537,
		encodeExponent(3):                      3,
		encodeExponent(0x7f, 0xff, 0xff, 0xff): 1<<31 - 1,
		encodeExponent(0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1): 65537, // zero-padded past 8 bytes
	}
	for jwkE, want := range valid {
		got, err := getPublicExponent(jwkE)
		require.NoError(t, err, "exponent %q", jwkE)
		assert.Equal(t, want, got, "exponent %q", jwkE)
	}

	invalid := []string{
		"",
		encodeExponent(0),
		encodeExponent(1),
		encodeExponent(4),
		encodeExponent(0x80, 0, 0, 1),
		encodeExponent(0x80, 0, 0, 0, 0, 0, 0, 1),
		encodeExponent(1, 0, 0, 0, 0, 0, 0, 0, 1),
	}
	for _, jwkE := range invalid {
		assert.NotPanics(t, func() {
			_, err := getPublicExponent(jwkE)
			assert.Error(t, err, "exponent %q", jwkE)
		})
	}
}
