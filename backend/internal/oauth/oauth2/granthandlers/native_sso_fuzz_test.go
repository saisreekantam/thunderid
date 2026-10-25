// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package granthandlers

import (
	"slices"
	"testing"

	"github.com/thunder-id/thunderid/internal/oauth/oauth2/constants"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/model"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/tokenservice"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// FuzzNativeSSOScopes checks the Native SSO scope invariants for any requested scope string: the
// granted scopes are a subset of the original grant and of the client's registration, always
// include openid, and never include device_sso.
func FuzzNativeSSOScopes(f *testing.F) {
	ds := &providers.DeviceSecretClaims{Scopes: []string{"openid", "profile", "email", "vc:issue"}}
	app := &providers.OAuthClient{Scopes: []string{"openid", "profile", "vc:issue", constants.ScopeDeviceSSO}}

	for _, seed := range []string{"", "openid", "openid profile", "openid email", "profile",
		"openid device_sso", "openid  profile  vc:issue", "openid phone", "\topenid\nprofile"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, scope string) {
		req := &model.TokenRequest{Scope: scope}
		if errResp := validateNativeSSOExchangeRequest(&model.TokenRequest{
			Scope: scope, SubjectTokenType: string(constants.TokenTypeIdentifierIDToken),
		}); errResp != nil {
			return
		}
		granted, errResp := nativeSSOScopes(req, ds, app)
		if errResp != nil {
			return
		}
		if !slices.Contains(granted, constants.ScopeOpenID) {
			t.Fatalf("granted %v without openid for %q", granted, scope)
		}
		for _, s := range granted {
			if s == constants.ScopeDeviceSSO {
				t.Fatalf("granted device_sso for %q", scope)
			}
			if !slices.Contains(ds.Scopes, s) || (s != constants.ScopeOpenID && !slices.Contains(app.Scopes, s)) {
				t.Fatalf("granted %q outside the original grant or registration for %q", s, scope)
			}
		}
		if len(tokenservice.ParseScopes(scope)) == 0 && !slices.Equal(granted, ds.Scopes) {
			t.Fatalf("empty request did not default to the original grant: %v", granted)
		}
	})
}
