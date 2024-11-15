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
	"github.com/AccelByte/go-restful-plugins/v3/pkg/jaeger"
	"github.com/bluele/gcache"
	"github.com/pkg/errors"
	"go.uber.org/atomic"
	"net/http"
	"strings"
	"time"
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
	span, _ := jaeger.StartSpanFromContext(options, "client.ValidateAccessToken")
	defer jaeger.Finish(span)
	return client.validateAccessToken(accessToken, span)
}

func (client *DefaultClient) ValidateAndParseClaims(accessToken string) (*JWTClaims, error) {
	options := context.TODO()
	span, _ := jaeger.StartSpanFromContext(options, "client.ValidateAndParseClaims")
	defer jaeger.Finish(span)

	claim, err := client.validateJWT(accessToken, span)
	if err != nil {
		if err == errTokenExpired {
			jaeger.TraceError(span, err)
			return nil, err
		}
		err = logAndReturnErr(
			errors.WithMessage(err,
				"ValidateAndParseClaims: unable to validate JWT"))
		jaeger.TraceError(span, err)
		return nil, err
	}
	return claim, nil
}

func (client *DefaultClient) ValidatePermission(
	claims *JWTClaims,
	requiredPermission Permission,
	permissionResources map[string]string,
) (bool, error) {
	if claims == nil {
		log("ValidatePermission: claim is nil")
		return false, nil
	}

	span, _ := jaeger.StartSpanFromContext(context.TODO(), "client.ValidatePermission")
	defer jaeger.Finish(span)

	for placeholder, value := range permissionResources {
		requiredPermission.Resource = strings.Replace(requiredPermission.Resource, placeholder, value, 1)
	}

	// if the request is coming from a client (i.e. no claims.sub), we want to check using the client's permissions and
	// organizationID
	if claims.Subject == "" {
		ownedPermissions := client.applyUserPermissionResourceValues(claims.Permissions, claims, claims.OrganizationID, "")
		if client.permissionAllowed(ownedPermissions, requiredPermission) {
			return true, nil
		}
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
	span, _ := jaeger.StartSpanFromContext(options, "client.ClientToken")
	defer jaeger.Finish(span)

	token, err := client.clientAccessToken.Get("")
	if err != nil {
		return "", errors.Errorf("failed to load client token, %s", err.Error())
	}
	return token.(string), nil
}

func (client *DefaultClient) GetClientInformation(clientID string) (*ClientInformation, error) {
	options := context.TODO()
	span, _ := jaeger.StartSpanFromContext(options, "client.GetClientInformation")
	defer jaeger.Finish(span)

	clientInfo, err := client.clientInfoCache.Get(clientID)
	if err != nil {
		return nil, errors.Errorf("failed to load client info, %s", err.Error())
	}
	info := clientInfo.(*ClientInformation)
	return info, nil
}

func (client *DefaultClient) GetRolePermissions(roleID string) (perms []Permission, err error) {
	options := context.TODO()
	span, _ := jaeger.StartSpanFromContext(options, "client.GetRolePermissions")
	defer jaeger.Finish(span)

	roleInfo, err := client.roleInfoCache.Get(roleID)
	if err != nil {
		return nil, errors.Errorf("failed to load permission info, %s", err.Error())
	}
	info := roleInfo.(*Role)
	return info.Permissions, nil
}

func (client *DefaultClient) GetKeys() (keys map[string]*rsa.PublicKey, err error) {
	options := context.TODO()
	span, _ := jaeger.StartSpanFromContext(options, "client.GetKeys")
	defer jaeger.Finish(span)

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
