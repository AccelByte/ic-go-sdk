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
	"context"
	"crypto/rsa"
	"net/http"
	"strings"
	"time"

	"github.com/AccelByte/ic-go-sdk/internal/tracing"
	"github.com/bluele/gcache"
	"github.com/pkg/errors"
	"go.uber.org/atomic"
)

const (
	defaultTokenRefreshRate = 0.8
	maxBackOffTime          = 65 * time.Second
)

type Config struct {
	BaseURL      string
	ClientID     string
	ClientSecret string
	Debug        bool
}

// DefaultClient define oauth client config
type DefaultClient struct {
	clientAccessToken gcache.Cache
	config            *Config

	jwksRefreshError  error
	tokenRefreshError atomic.Error
	clientInfoCache   gcache.Cache
	roleInfoCache     gcache.Cache
	keysCache         gcache.Cache
	// for easily mocking the HTTP call
	httpClient HTTPClient
}

var debug atomic.Bool

func NewDefaultClient(config *Config) *DefaultClient {
	client := &DefaultClient{
		config:     config,
		httpClient: &http.Client{},
	}
	client.clientAccessToken = gcache.New(1).LRU().
		LoaderExpireFunc(func(i interface{}) (interface{}, *time.Duration, error) {
			token, ttl, err := client.ClientTokenGrant()
			return token, ttl, err
		}).Build()

	client.keysCache = gcache.New(100).LRU().
		LoaderExpireFunc(func(i interface{}) (interface{}, *time.Duration, error) {
			keys, err := client.getJWKS()
			ttl := time.Minute
			return keys, &ttl, err
		}).Build()
	client.clientInfoCache = gcache.New(100).LRU().
		LoaderExpireFunc(func(clientID interface{}) (interface{}, *time.Duration, error) {
			clientInfo, err := client.fetchClientInformation(clientID.(string))
			ttl := time.Minute
			return clientInfo, &ttl, err
		}).Build()
	client.roleInfoCache = gcache.New(100).LRU().
		LoaderExpireFunc(func(roleID interface{}) (interface{}, *time.Duration, error) {
			roleInfo, err := client.getRoleInfo(roleID.(string))
			ttl := time.Minute
			return roleInfo, &ttl, err
		}).Build()
	debug.Store(config.Debug)
	return client
}

func (client *DefaultClient) ValidateAccessToken(accessToken string) (bool, error) {
	options := context.TODO()
	span, _ := tracing.StartSpanFromContext(options, "client.ValidateAccessToken")
	defer tracing.Finish(span)
	return client.validateAccessToken(accessToken, span)
}

func (client *DefaultClient) ValidateAndParseClaims(accessToken string) (*JWTClaims, error) {
	options := context.TODO()
	span, _ := tracing.StartSpanFromContext(options, "client.ValidateAndParseClaims")
	defer tracing.Finish(span)

	claim, err := client.validateJWT(accessToken, span)
	if err != nil {
		if err == errTokenExpired {
			tracing.TraceError(span, err)
			return nil, err
		}
		err = logAndReturnErr(
			errors.WithMessage(err,
				"ValidateAndParseClaims: unable to validate JWT"))
		tracing.TraceError(span, err)
		return nil, err
	}
	return claim, nil
}

func (client *DefaultClient) ValidatePermission(claims *JWTClaims, requiredPermission Permission,
	permissionResources map[string]string) (bool, error) {
	options := context.TODO()
	span, _ := tracing.StartSpanFromContext(options, "client.ValidatePermission")
	defer tracing.Finish(span)

	if claims == nil {
		log("ValidatePermission: claim is nil")
		return false, nil
	}
	for placeholder, value := range permissionResources {
		requiredPermission.Resource = strings.Replace(requiredPermission.Resource, placeholder, value, 1)
	}

	if client.permissionAllowed(claims.Permissions, requiredPermission) {
		return true, nil
	}

	for _, role := range claims.Roles {
		rolePermission, err := client.GetRolePermissions(role.RoleID)
		if err != nil {
			return false, err
		}
		ownedPermissions := client.applyUserPermissionResourceValues(rolePermission, claims, role.OrganizationID, role.ProjectID)
		if client.permissionAllowed(ownedPermissions, requiredPermission) {
			return true, nil
		}
	}
	return false, nil
}

func (client *DefaultClient) ClientToken() (string, error) {
	options := context.TODO()
	span, _ := tracing.StartSpanFromContext(options, "client.ClientToken")
	defer tracing.Finish(span)

	token, err := client.clientAccessToken.Get("")
	if err != nil {
		return "", errors.Errorf("failed to load client token, %s", err.Error())
	}
	return token.(string), nil
}

func (client *DefaultClient) GetClientInformation(clientID string) (*ClientInformation, error) {
	options := context.TODO()
	span, _ := tracing.StartSpanFromContext(options, "client.GetClientInformation")
	defer tracing.Finish(span)

	clientInfo, err := client.clientInfoCache.Get(clientID)
	if err != nil {
		return nil, errors.Errorf("failed to load client info, %s", err.Error())
	}
	info := clientInfo.(*ClientInformation)
	return info, nil
}

func (client *DefaultClient) GetRolePermissions(roleID string) (perms []Permission, err error) {
	options := context.TODO()
	span, _ := tracing.StartSpanFromContext(options, "client.GetRolePermissions")
	defer tracing.Finish(span)

	roleInfo, err := client.roleInfoCache.Get(roleID)
	if err != nil {
		return nil, errors.Errorf("failed to load permission info, %s", err.Error())
	}
	info := roleInfo.(*Role)
	return info.Permissions, nil
}

func (client *DefaultClient) GetKeys() (keys map[string]*rsa.PublicKey, err error) {
	options := context.TODO()
	span, _ := tracing.StartSpanFromContext(options, "client.GetKeys")
	defer tracing.Finish(span)

	keysV, err := client.keysCache.Get("")
	if err != nil {
		return nil, errors.Errorf("failed to load permission info, %s", err.Error())
	}
	keys = keysV.(map[string]*rsa.PublicKey)
	return keys, nil
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}
