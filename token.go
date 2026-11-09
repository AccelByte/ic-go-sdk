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
	"github.com/AccelByte/go-jose/jwt"
	"github.com/AccelByte/ic-go-sdk/internal/tracing"
	"github.com/cenkalti/backoff"
	"github.com/opentracing/opentracing-go"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/url"
)

// nolint: funlen
func (client *DefaultClient) validateAccessToken(accessToken string, rootSpan opentracing.Span) (bool, error) {
	span := tracing.StartChildSpan(rootSpan, "client.validateAccessToken")
	defer tracing.Finish(span)

	form := url.Values{}
	form.Add("token", accessToken)

	req, err := http.NewRequest(http.MethodPost, client.config.BaseURL+verifyPath, bytes.NewBufferString(form.Encode()))
	if err != nil {
		tracing.TraceError(span, errors.Wrap(err, "validateAccessToken: unable to create new HTTP request"))
		return false, errors.Wrap(err, "validateAccessToken: unable to create new HTTP request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.config.ClientID, client.config.ClientSecret)

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	var responseStatusCode int

	err = backoff.
		Retry(
			func() error {
				reqSpan := tracing.StartChildSpan(span, "HTTP Request: "+req.Method+" "+req.URL.Path)
				defer tracing.Finish(reqSpan)
				jErr := tracing.InjectSpanIntoRequest(reqSpan, req)
				if jErr != nil {
					logrus.Warn(jErr)
				}
				resp, e := client.httpClient.Do(req)
				if e != nil {
					tracing.TraceError(reqSpan, e)
					return backoff.Permanent(e)
				}
				defer resp.Body.Close()

				responseStatusCode = resp.StatusCode
				if resp.StatusCode >= http.StatusInternalServerError {
					tracing.TraceError(
						reqSpan,
						errors.Errorf(
							"validateAccessToken: endpoint returned status code : %v",
							responseStatusCode,
						),
					)

					return errors.Errorf("validateAccessToken: endpoint returned status code : %v", responseStatusCode)
				}

				return nil
			},
			b,
		)

	if err != nil {
		tracing.TraceError(span, errors.Wrap(err, "validateAccessToken: unable to do HTTP request"))
		return false, errors.Wrap(err, "validateAccessToken: unable to do HTTP request")
	}

	if responseStatusCode == http.StatusUnauthorized {
		tracing.TraceError(span, errors.Wrap(errUnauthorized, "validateAccessToken: unauthorized"))
		return false, errors.Wrap(errUnauthorized, "validateAccessToken: unauthorized")
	}

	if responseStatusCode != http.StatusOK {
		return false, errors.Errorf("validateAccessToken: unable to validate access token: error code : %d",
			responseStatusCode)
	}

	return true, nil
}

func (client *DefaultClient) validateJWT(token string, rootSpan opentracing.Span) (*JWTClaims, error) {
	span := tracing.StartChildSpan(rootSpan, "client.validateJWT")
	defer tracing.Finish(span)

	if token == "" {
		return nil, errors.WithMessage(errEmptyToken, "validateJWT: invalid token")
	}

	jwtClaims := JWTClaims{}

	webToken, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, errors.Wrap(err, "validateJWT: unable to parse JWT")
	}

	if webToken.Headers[0].KeyID == "" {
		return nil, errors.WithMessage(errInvalidTokenSignatureKey, "validateJWT: invalid header")
	}

	publicKey, err := client.getPublicKey(webToken.Headers[0].KeyID)
	if err != nil {
		return nil, errors.WithMessage(err, "validateJWT: invalid key")
	}

	err = webToken.Claims(publicKey, &jwtClaims)
	if err != nil {
		return nil, errors.Wrap(err, "validateJWT: unable to deserialize JWT claims")
	}

	err = jwtClaims.Validate()
	if err != nil {
		if err == jwt.ErrExpired {
			return nil, errTokenExpired
		}
		return nil, errors.Wrap(err, "validateJWT: unable to validate JWT")
	}

	return &jwtClaims, nil
}
