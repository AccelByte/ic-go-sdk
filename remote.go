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
	"encoding/json"
	"fmt"
	"github.com/AccelByte/ic-go-sdk/internal/tracing"
	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

const (
	jwksPath              = "/v1/oauth/jwks"
	grantPath             = "/v1/oauth/token"
	verifyPath            = "/v1/oauth/verify"
	getRolePath           = "/v1/admin/roles/%s"
	clientInformationPath = "/v1/admin/clients/%s"
)

func (client *DefaultClient) fetchClientInformation(clientID string, opts ...Option) (clientInfo *ClientInformation, err error) {
	options := processOptions(opts)
	span, _ := tracing.StartSpanFromContext(options.traceCtx, "client.fetchClientInformation")

	defer tracing.Finish(span)

	getClientInformationURL := client.config.BaseURL + fmt.Sprintf(clientInformationPath, clientID)
	req, err := http.NewRequest(http.MethodGet, getClientInformationURL, nil)
	if err != nil {
		return nil, errors.Wrap(err, "getClientInformation: unable to create new HTTP request")
	}

	req.Header.Add("Content-Type", "application/json")

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	var responseStatusCode int

	var responseBodyBytes []byte

	// nolint: dupl
	err = backoff.
		Retry(
			func() error {
				var e error
				clientToken, e := client.ClientToken()
				if e != nil {
					logErr(e)
				}
				req.Header.Set("Authorization", "Bearer "+clientToken)

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
					return errors.Errorf("getClientInformation: endpoint returned status code : %v", responseStatusCode)
				} else if resp.StatusCode == http.StatusUnauthorized {
					tracing.TraceError(span, errors.Wrap(errUnauthorized, "getClientInformation: unauthorized"))
					return errors.Wrap(errUnauthorized, "getClientInformation: unauthorized")
				}

				responseBodyBytes, e = ioutil.ReadAll(resp.Body)
				if e != nil {
					tracing.TraceError(reqSpan, fmt.Errorf("Body.ReadAll: %s", e))
					return errors.Wrap(e, "getClientInformation: unable to read body response")
				}

				return nil
			},
			b,
		)

	if err != nil {
		tracing.TraceError(span, errors.Wrap(err, "getClientInformation: unable to do HTTP request"))
		return nil, errors.Wrap(err, "getClientInformation: unable to do HTTP request")
	}

	if responseStatusCode != http.StatusOK {
		tracing.TraceError(span,
			errors.Errorf(
				"getClientInformation: unable to get client information: error code : %d, error message : %s",
				responseStatusCode, string(responseBodyBytes)))

		return nil, errors.Errorf("getClientInformation: unable to get client information: error code : %d, error message : %s",
			responseStatusCode, string(responseBodyBytes))
	}

	var clientInformation ClientInformation
	err = json.Unmarshal(responseBodyBytes, &clientInformation)
	if err != nil {
		tracing.TraceError(span, errors.Wrap(err, "getClientInformation: unable to unmarshal response body"))
		return nil, errors.Wrap(err, "getClientInformation: unable to unmarshal response body")
	}

	return &clientInformation, nil
}

func (client *DefaultClient) ClientTokenGrant(opts ...Option) (token string, ttl *time.Duration, err error) {
	options := processOptions(opts)
	span, _ := tracing.StartSpanFromContext(options.traceCtx, "client.ClientTokenGrant")

	defer tracing.Finish(span)

	form := url.Values{}
	form.Add("grant_type", "client_credentials")

	req, err := http.NewRequest(
		http.MethodPost,
		client.config.BaseURL+grantPath,
		bytes.NewBufferString(form.Encode()),
	)
	if err != nil {
		tracing.TraceError(span, errors.Wrap(err, "ClientTokenGrant: unable to create new HTTP request"))
		return "", nil, errors.Wrap(err, "ClientTokenGrant: unable to create new HTTP request")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.config.ClientID, client.config.ClientSecret)

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	var responseStatusCode int

	var responseBodyBytes []byte

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
					return backoff.Permanent(e)
				}
				defer resp.Body.Close()

				responseStatusCode = resp.StatusCode
				if resp.StatusCode >= http.StatusInternalServerError {
					tracing.TraceError(reqSpan, fmt.Errorf("StatusCode: %v", resp.StatusCode))
					return errors.Errorf("ClientTokenGrant: endpoint returned status code : %v", responseStatusCode)
				}

				responseBodyBytes, e = ioutil.ReadAll(resp.Body)
				if e != nil {
					tracing.TraceError(reqSpan, fmt.Errorf("Body.ReadAll: %s", e))
					return errors.Wrap(e, "ClientTokenGrant: unable to read response body")
				}

				return nil
			},
			b,
		)

	if err != nil {
		tracing.TraceError(span, errors.Wrap(err, "ClientTokenGrant: unable to do HTTP request"))
		return "", nil, errors.Wrap(err, "ClientTokenGrant: unable to do HTTP request")
	}

	if responseStatusCode != http.StatusOK {
		tracing.TraceError(
			span,
			errors.Errorf(
				"ClientTokenGrant: unable to grant client token: error code : %d, error message : %s",
				responseStatusCode,
				string(responseBodyBytes),
			),
		)

		return "", nil, errors.Errorf("ClientTokenGrant: unable to grant client token: error code : %d, error message : %s",
			responseStatusCode, string(responseBodyBytes))
	}

	var tokenResponse *TokenResponse

	err = json.Unmarshal(responseBodyBytes, &tokenResponse)
	if err != nil {
		tracing.TraceError(span, errors.Wrap(err, "clientDelegateTokenGrant: unable to unmarshal response body"))
		return "", nil, errors.Wrap(err, "clientDelegateTokenGrant: unable to unmarshal response body")
	}
	refreshInterval := time.Duration(float64(tokenResponse.ExpiresIn)*defaultTokenRefreshRate) * time.Second
	return tokenResponse.AccessToken, &refreshInterval, nil
}

// nolint: funlen, dupl
func (client *DefaultClient) getRoleInfo(roleID string, opts ...Option) (*Role, error) {
	options := processOptions(opts)
	span, _ := tracing.StartSpanFromContext(options.traceCtx, "client.getRoleInfo")

	defer tracing.Finish(span)

	req, err := http.NewRequest("GET", client.config.BaseURL+fmt.Sprintf(getRolePath, roleID), nil)
	if err != nil {
		return nil, errors.Wrap(err, "getRolePermission: unable to create new HTTP request")
	}
	clientToken, err := client.ClientToken()
	if err != nil {
		return nil, err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+clientToken)

	b := backoff.NewExponentialBackOff()
	b.MaxElapsedTime = maxBackOffTime

	var responseStatusCode int

	var responseBodyBytes []byte

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
					return backoff.Permanent(e)
				}
				defer resp.Body.Close()

				responseStatusCode = resp.StatusCode
				if resp.StatusCode >= http.StatusInternalServerError {
					tracing.TraceError(reqSpan, fmt.Errorf("StatusCode: %v", resp.StatusCode))
					return errors.Errorf("getRolePermission: endpoint returned status code : %v", responseStatusCode)
				}

				responseBodyBytes, e = ioutil.ReadAll(resp.Body)
				if e != nil {
					tracing.TraceError(reqSpan, fmt.Errorf("Body.ReadAll: %s", e))
					return errors.Wrap(e, "getRolePermission: unable to read response body")
				}

				return nil
			},
			b,
		)

	if err != nil {
		tracing.TraceError(span, errors.Wrap(err, "getRolePermission: unable to do HTTP request"))
		return nil, errors.Wrap(err, "getRolePermission: unable to do HTTP request")
	}

	switch responseStatusCode {
	case http.StatusOK:
		// do nothing
	case http.StatusUnauthorized:
		tracing.TraceError(span, errors.Wrap(errUnauthorized, "getRolePermission: unauthorized"))
		return nil, errors.Wrap(errUnauthorized, "getRolePermission: unauthorized")
	case http.StatusForbidden:
		tracing.TraceError(span, errors.Wrap(errForbidden, "getRolePermission: forbidden"))
		return nil, errors.Wrap(errForbidden, "getRolePermission: forbidden")
	case http.StatusNotFound:
		tracing.TraceError(span, errors.Wrap(errRoleNotFound, "getRolePermission: not found"))
		return nil, errors.Wrap(errRoleNotFound, "getRolePermission: not found")
	default:
		tracing.TraceError(span, errors.New("unexpected error: "+http.StatusText(responseStatusCode)))
		return nil, errors.New("unexpected error: " + http.StatusText(responseStatusCode))
	}

	var role Role

	err = json.Unmarshal(responseBodyBytes, &role)
	if err != nil {
		tracing.TraceError(span, errors.Wrap(err, "getRolePermission: unable to unmarshal response body"))
		return nil, errors.Wrap(err, "getRolePermission: unable to unmarshal response body")
	}
	return &role, nil
}
