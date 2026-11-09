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

import "context"

type Client interface {
	ClientToken() (string, error)

	ValidateAccessToken(accessToken string) (bool, error)

	ValidateAndParseClaims(accessToken string) (*JWTClaims, error)

	// ValidatePermission validates if an access token has right for a specific permission
	// requiredPermission: permission to access resource, example:
	// 		{Resource: "ORG:{organizationId}:USER:{userId}:PROJ:{projectId}", Action: 2}
	// permissionResources: resource string to replace the `{}` placeholder in `requiredPermission`
	ValidatePermission(claims *JWTClaims, requiredPermission Permission,
		permissionResources map[string]string) (bool, error)

	GetRolePermissions(roleID string) (perms []Permission, err error)

	GetClientInformation(clientID string) (*ClientInformation, error)
}

type Options struct {
	traceCtx context.Context
}

type Option func(*Options)

func processOptions(opts []Option) *Options {
	options := &Options{}

	for _, opt := range opts {
		opt(options)
	}
	return options
}
