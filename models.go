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
	"time"

	"github.com/AccelByte/go-jose/jwt"
)

const (
	ActionCreate = 1
	ActionRead   = 1 << 1
	ActionUpdate = 1 << 2
	ActionDelete = 1 << 3
)

type TokenResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	IDToken      string   `json:"id_token"`
	ExpiresIn    int      `json:"expires_in"`
	TokenType    string   `json:"token_type"`
	Roles        []string `json:"roles"`
	UserID       string   `json:"user_id"`
}

type Permission struct {
	Resource string `json:"resource"`
	Action   int    `json:"action"`
}

type ClientInformation struct {
	ClientName     string `json:"clientName"`
	RedirectURI    string `json:"redirectUri"`
	BaseURI        string `json:"baseUri"`
	OrganizationID string `json:"organizationId"`
}

type Role struct {
	RoleID      string       `json:"roleId"`
	Permissions []Permission `json:"permissions"`
}

type ClaimRole struct {
	RoleID         string `json:"roleId"`
	OrganizationID string `json:"organizationId,omitempty" description:"if the role scope is ORG, then organizationId is required"`
	ProjectID      string `json:"projectId,omitempty" description:"if the role scope is PROJ, then projectId is required"`
}

// JWTClaims holds data stored in a JWT access token with additional Justice Flags field
type JWTClaims struct {
	OrganizationID string       `json:"organizationId"`
	DisplayName    string       `json:"display_name"`
	Roles          []ClaimRole  `json:"roles"`
	Scope          string       `json:"scope"`
	ClientID       string       `json:"client_id"`
	Permissions    []Permission `json:"permissions"`
	jwt.Claims
}

// Validate checks if the JWT is still valid
func (c *JWTClaims) Validate() error {
	return c.Claims.Validate(jwt.Expected{
		Time: time.Now().UTC(),
	})
}
