// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package granthandlers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/attributecache"
	oauthconfig "github.com/thunder-id/thunderid/internal/oauth/config"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/authz"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/constants"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/dpop"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/model"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/revocation"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/tokenservice"
	"github.com/thunder-id/thunderid/internal/system/jose/jwt"
	tidcommon "github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	engineconfig "github.com/thunder-id/thunderid/pkg/thunderidengine/config"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
	"github.com/thunder-id/thunderid/tests/mocks/actorprovidermock"
	"github.com/thunder-id/thunderid/tests/mocks/attributecachemock"
	"github.com/thunder-id/thunderid/tests/mocks/devicesecretprovidermock"
	"github.com/thunder-id/thunderid/tests/mocks/jose/jwtmock"
	"github.com/thunder-id/thunderid/tests/mocks/nativessoconsentprovidermock"
	"github.com/thunder-id/thunderid/tests/mocks/oauth/oauth2/tokenservicemock"
	"github.com/thunder-id/thunderid/tests/mocks/resourcemock"
)

const (
	nativeSSOIssuer       = "https://esignet.example.com"
	nativeSSOSuperApp     = "super-app"
	nativeSSOChildApp     = "child-app"
	nativeSSOSubject      = "psut-123"
	nativeSSOSessionID    = "sid-1"
	nativeSSODeviceKey    = "jkt-device-key-a"
	nativeSSODeviceSecret = "h.k.iv.ct.tag" //nolint:gosec // Test fixture, not a credential.
)

type NativeSSOTestSuite struct {
	suite.Suite
	jwtService   *jwtmock.JWTServiceInterfaceMock
	tokenBuilder *tokenservicemock.TokenBuilderInterfaceMock
	actors       *actorprovidermock.ActorProviderMock
	deviceSecret *devicesecretprovidermock.DeviceSecretProviderMock
	consent      *nativessoconsentprovidermock.NativeSSOConsentProviderMock
	resources    *resourcemock.ResourceServiceInterfaceMock
	attrCache    *attributecachemock.AttributeCacheServiceInterfaceMock
	handler      *tokenExchangeGrantHandler
	childApp     *providers.OAuthClient
	superApp     *providers.OAuthClient
	dsClaims     *providers.DeviceSecretClaims
}

func TestNativeSSOTestSuite(t *testing.T) {
	suite.Run(t, new(NativeSSOTestSuite))
}

func (ts *NativeSSOTestSuite) SetupTest() {
	ts.jwtService = jwtmock.NewJWTServiceInterfaceMock(ts.T())
	ts.tokenBuilder = tokenservicemock.NewTokenBuilderInterfaceMock(ts.T())
	ts.actors = actorprovidermock.NewActorProviderMock(ts.T())
	ts.deviceSecret = devicesecretprovidermock.NewDeviceSecretProviderMock(ts.T())
	ts.consent = nativessoconsentprovidermock.NewNativeSSOConsentProviderMock(ts.T())
	ts.resources = resourcemock.NewResourceServiceInterfaceMock(ts.T())
	ts.attrCache = attributecachemock.NewAttributeCacheServiceInterfaceMock(ts.T())
	ts.handler = &tokenExchangeGrantHandler{
		tokenBuilder:    ts.tokenBuilder,
		resourceService: ts.resources,
		attributeCache:  ts.attrCache,
		jwtService:      ts.jwtService,
		actorProvider:   ts.actors,
		nativeSSO:       NativeSSODependencies{DeviceSecret: ts.deviceSecret, Consent: ts.consent},
		cfg:             oauthconfig.Config{JWT: engineconfig.JWTConfig{Issuer: nativeSSOIssuer}},
	}
	ts.childApp = &providers.OAuthClient{
		ID:         nativeSSOChildApp,
		ClientID:   nativeSSOChildApp,
		GrantTypes: []providers.GrantType{providers.GrantTypeTokenExchange},
		Scopes:     []string{"openid", "profile", "email"},
	}
	ts.superApp = &providers.OAuthClient{
		ID:       nativeSSOSuperApp,
		ClientID: nativeSSOSuperApp,
		Scopes:   []string{"openid", "profile", "email", constants.ScopeDeviceSSO},
	}
	ts.dsClaims = &providers.DeviceSecretClaims{
		ID:               "ds-jti",
		Issuer:           nativeSSOIssuer,
		Subject:          nativeSSOSubject,
		SessionID:        nativeSSOSessionID,
		ClientID:         nativeSSOSuperApp,
		Scopes:           []string{"openid", "profile", "email"},
		CnfJkt:           nativeSSODeviceKey,
		AttributeCacheID: "aci-1",
		ExpiresAt:        time.Now().Add(time.Hour),
	}
}

// idToken builds a compact JWS whose signature the JWT service mock accepts.
func (ts *NativeSSOTestSuite) idToken(overrides map[string]interface{}) string {
	claims := map[string]interface{}{
		constants.ClaimIss:              nativeSSOIssuer,
		constants.ClaimSub:              nativeSSOSubject,
		constants.ClaimAud:              nativeSSOSuperApp,
		constants.ClaimSessionID:        nativeSSOSessionID,
		constants.ClaimDeviceSecretHash: deviceSecretHash(nativeSSODeviceSecret),
		constants.ClaimExp:              time.Now().Add(-time.Hour).Unix(), // expired: must still be accepted
	}
	for k, v := range overrides {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc(header) + "." + enc(payload) + ".c2ln"
}

func (ts *NativeSSOTestSuite) request(scope string, idToken string) *model.TokenRequest {
	return &model.TokenRequest{
		GrantType:        string(providers.GrantTypeTokenExchange),
		ClientID:         nativeSSOChildApp,
		Scope:            scope,
		SubjectToken:     idToken,
		SubjectTokenType: string(constants.TokenTypeIdentifierIDToken),
		ActorToken:       nativeSSODeviceSecret,
		ActorTokenType:   string(constants.TokenTypeIdentifierDeviceSecret),
	}
}

func dpopCtx(jkt string) context.Context {
	return dpop.WithJkt(context.Background(), jkt)
}

// expectValidCredentials wires the mocks for a request whose ID token and device secret are valid.
func (ts *NativeSSOTestSuite) expectValidCredentials() {
	ts.jwtService.EXPECT().VerifyJWTSignature(mock.Anything, mock.Anything).Return(nil)
	ts.deviceSecret.EXPECT().ValidateDeviceSecret(mock.Anything, nativeSSOChildApp, nativeSSODeviceSecret).
		Return(ts.dsClaims, nil)
}

func (ts *NativeSSOTestSuite) TestExchangeSucceedsAndBindsTokenToDeviceKey() {
	ts.expectValidCredentials()
	ts.actors.EXPECT().GetOAuthClientByClientID(mock.Anything, nativeSSOSuperApp).Return(ts.superApp, nil)
	ts.consent.EXPECT().ResolveNativeSSOConsent(mock.Anything, mock.MatchedBy(
		func(r *providers.NativeSSOConsentRequest) bool {
			return r.ClientID == nativeSSOChildApp && r.OriginalClientID == nativeSSOSuperApp &&
				r.Subject == nativeSSOSubject && r.SessionID == nativeSSOSessionID
		})).Return(&providers.NativeSSOConsentResult{Covered: true,
		ReleasableClaims: []string{"name", "birthdate"}}, nil)
	ts.deviceSecret.EXPECT().MarkDeviceSecretUsed(mock.Anything, ts.dsClaims, nativeSSOChildApp).Return(nil)
	// The identity system's record was issued to the Super App and carries more than the child may see.
	ts.attrCache.EXPECT().GetAttributeCache(mock.Anything, "aci-1").Return(&attributecache.AttributeCache{
		ID: "aci-1", Attributes: map[string]interface{}{providers.RawJWTAttributeKey: kycRecord(map[string]interface{}{
			"aud": nativeSSOSuperApp, "name": "Asha", "birthdate": "1990/01/01", "email": "asha@example.com",
		})},
	}, nil)
	ts.attrCache.EXPECT().CreateAttributeCache(mock.Anything, mock.MatchedBy(func(c *attributecache.AttributeCache) bool {
		return len(c.Attributes) == 2 && c.Attributes["name"] == "Asha" && c.Attributes["birthdate"] == "1990/01/01" &&
			c.TTLSeconds > 0
	})).Return(&attributecache.AttributeCache{ID: "aci-child"}, nil)
	ts.tokenBuilder.EXPECT().BuildAccessToken(mock.Anything, mock.MatchedBy(
		func(c *tokenservice.AccessTokenBuildContext) bool {
			return c.Subject == nativeSSOSubject && c.ClientID == nativeSSOChildApp &&
				c.DPoPJkt == nativeSSODeviceKey && c.AttributeCacheID == "aci-child" &&
				c.TokenFamilyID == nativeSSOTokenFamilyPrefix+nativeSSOSessionID &&
				c.ActorClaims != nil && c.ActorClaims.Sub == nativeSSOSuperApp &&
				c.GrantType == string(providers.GrantTypeTokenExchange) &&
				len(c.Scopes) == 2 && c.Scopes[0] == "openid" && c.Scopes[1] == "profile"
		})).Return(&model.TokenDTO{Token: "child-access-token", TokenType: constants.TokenTypeDPoP}, nil)
	ts.consent.EXPECT().RecordNativeSSOConsent(mock.Anything, mock.Anything).Return(nil)

	resp, errResp := ts.handler.HandleGrant(dpopCtx(nativeSSODeviceKey),
		ts.request("openid profile", ts.idToken(nil)), ts.childApp)

	ts.Require().Nil(errResp)
	ts.Equal("child-access-token", resp.AccessToken.Token)
	ts.Equal(constants.TokenTypeDPoP, resp.AccessToken.TokenType)
}

// kycRecord builds an identity-system user record as returned by kyc-exchange (a signed JWT).
func kycRecord(claims map[string]interface{}) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256"})
	payload, _ := json.Marshal(claims)
	enc := base64.RawURLEncoding.EncodeToString
	return enc(header) + "." + enc(payload) + ".c2ln"
}

func (ts *NativeSSOTestSuite) expectCoveredExchange(releasable []string) {
	ts.expectValidCredentials()
	ts.actors.EXPECT().GetOAuthClientByClientID(mock.Anything, nativeSSOSuperApp).Return(ts.superApp, nil)
	ts.consent.EXPECT().ResolveNativeSSOConsent(mock.Anything, mock.Anything).
		Return(&providers.NativeSSOConsentResult{Covered: true, ReleasableClaims: releasable}, nil)
	ts.deviceSecret.EXPECT().MarkDeviceSecretUsed(mock.Anything, mock.Anything, mock.Anything).Return(nil)
}

func (ts *NativeSSOTestSuite) TestChildAttributesFilterPlainAttributes() {
	ts.expectCoveredExchange([]string{"name"})
	ts.attrCache.EXPECT().GetAttributeCache(mock.Anything, "aci-1").Return(&attributecache.AttributeCache{
		Attributes: map[string]interface{}{"name": "Asha", "email": "asha@example.com"},
	}, nil)
	ts.attrCache.EXPECT().CreateAttributeCache(mock.Anything, mock.MatchedBy(func(c *attributecache.AttributeCache) bool {
		return len(c.Attributes) == 1 && c.Attributes["name"] == "Asha"
	})).Return(&attributecache.AttributeCache{ID: "aci-child"}, nil)
	ts.tokenBuilder.EXPECT().BuildAccessToken(mock.Anything, mock.MatchedBy(
		func(c *tokenservice.AccessTokenBuildContext) bool { return c.AttributeCacheID == "aci-child" })).
		Return(&model.TokenDTO{Token: "t"}, nil)
	ts.consent.EXPECT().RecordNativeSSOConsent(mock.Anything, mock.Anything).Return(nil)

	_, errResp := ts.handler.HandleGrant(dpopCtx(nativeSSODeviceKey), ts.request("openid profile", ts.idToken(nil)),
		ts.childApp)
	ts.Nil(errResp)
}

func (ts *NativeSSOTestSuite) TestChildAttributesRequireInteractionWhenUnavailable() {
	cases := []struct {
		name   string
		cache  *attributecache.AttributeCache
		svcErr *tidcommon.ServiceError
	}{
		{name: "encrypted identity record", cache: &attributecache.AttributeCache{
			Attributes: map[string]interface{}{providers.RawJWTAttributeKey: "h.k.iv.ct.tag"}}},
		{name: "login attributes expired", svcErr: &tidcommon.ServiceError{Type: tidcommon.ClientErrorType}},
	}
	for _, tc := range cases {
		ts.Run(tc.name, func() {
			ts.SetupTest()
			ts.expectCoveredExchange([]string{"name"})
			ts.attrCache.EXPECT().GetAttributeCache(mock.Anything, "aci-1").Return(tc.cache, tc.svcErr)

			_, errResp := ts.handler.HandleGrant(dpopCtx(nativeSSODeviceKey),
				ts.request("openid profile", ts.idToken(nil)), ts.childApp)
			ts.Require().NotNil(errResp)
			ts.Equal(constants.ErrorInteractionRequired, errResp.Error)
		})
	}
}

func (ts *NativeSSOTestSuite) TestExchangeDefaultsToOriginalScopes() {
	ts.expectValidCredentials()
	ts.actors.EXPECT().GetOAuthClientByClientID(mock.Anything, nativeSSOSuperApp).Return(ts.superApp, nil)
	ts.consent.EXPECT().ResolveNativeSSOConsent(mock.Anything, mock.Anything).
		Return(&providers.NativeSSOConsentResult{Covered: true}, nil)
	ts.deviceSecret.EXPECT().MarkDeviceSecretUsed(mock.Anything, mock.Anything, mock.Anything).Return(nil)
	ts.tokenBuilder.EXPECT().BuildAccessToken(mock.Anything, mock.MatchedBy(
		func(c *tokenservice.AccessTokenBuildContext) bool { return len(c.Scopes) == 3 })).
		Return(&model.TokenDTO{Token: "t"}, nil)
	ts.consent.EXPECT().RecordNativeSSOConsent(mock.Anything, mock.Anything).Return(nil)

	_, errResp := ts.handler.HandleGrant(dpopCtx(nativeSSODeviceKey), ts.request("", ts.idToken(nil)), ts.childApp)
	ts.Nil(errResp)
}

func (ts *NativeSSOTestSuite) TestOriginalClientSkipsConsent() {
	ts.jwtService.EXPECT().VerifyJWTSignature(mock.Anything, mock.Anything).Return(nil)
	ts.deviceSecret.EXPECT().ValidateDeviceSecret(mock.Anything, nativeSSOSuperApp, nativeSSODeviceSecret).
		Return(ts.dsClaims, nil)
	ts.actors.EXPECT().GetOAuthClientByClientID(mock.Anything, nativeSSOSuperApp).Return(ts.superApp, nil)
	ts.deviceSecret.EXPECT().MarkDeviceSecretUsed(mock.Anything, mock.Anything, nativeSSOSuperApp).Return(nil)
	ts.tokenBuilder.EXPECT().BuildAccessToken(mock.Anything, mock.Anything).Return(&model.TokenDTO{Token: "t"}, nil)

	req := ts.request("openid", ts.idToken(nil))
	req.ClientID = nativeSSOSuperApp
	_, errResp := ts.handler.HandleGrant(dpopCtx(nativeSSODeviceKey), req, ts.superApp)
	ts.Nil(errResp)
}

func (ts *NativeSSOTestSuite) TestRejectsWhenNativeSSODisabled() {
	ts.handler.nativeSSO = NativeSSODependencies{}
	_, errResp := ts.handler.HandleGrant(dpopCtx(nativeSSODeviceKey), ts.request("openid", ts.idToken(nil)),
		ts.childApp)
	ts.Require().NotNil(errResp)
	ts.Equal(constants.ErrorUnsupportedTokenType, errResp.Error)
}

func (ts *NativeSSOTestSuite) TestRejectsWithoutDPoPProof() {
	_, errResp := ts.handler.HandleGrant(context.Background(), ts.request("openid", ts.idToken(nil)), ts.childApp)
	ts.Require().NotNil(errResp)
	ts.Equal(constants.ErrorInvalidDPoPProof, errResp.Error)
}

func (ts *NativeSSOTestSuite) TestRejectsInvalidIDTokens() {
	cases := []struct {
		name      string
		token     string
		signature *tidcommon.ServiceError
	}{
		{name: "bad signature", token: ts.idToken(nil), signature: &jwt.ErrorInvalidTokenSignature},
		{name: "foreign issuer", token: ts.idToken(map[string]interface{}{constants.ClaimIss: "https://evil"})},
		{name: "missing ds_hash", token: ts.idToken(map[string]interface{}{constants.ClaimDeviceSecretHash: nil})},
		{name: "missing sid", token: ts.idToken(map[string]interface{}{constants.ClaimSessionID: nil})},
		{name: "refresh token", token: ts.idToken(map[string]interface{}{constants.ClaimAccessTokenSubject: "x"})},
		{name: "not a JWS", token: "a.b.c.d.e"},
	}
	for _, tc := range cases {
		ts.Run(tc.name, func() {
			ts.SetupTest()
			if tc.token != "a.b.c.d.e" {
				ts.jwtService.EXPECT().VerifyJWTSignature(mock.Anything, mock.Anything).Return(tc.signature)
			}
			_, errResp := ts.handler.HandleGrant(dpopCtx(nativeSSODeviceKey), ts.request("openid", tc.token),
				ts.childApp)
			ts.Require().NotNil(errResp)
			ts.Equal(constants.ErrorInvalidGrant, errResp.Error)
		})
	}
}

func (ts *NativeSSOTestSuite) TestMapsDeviceSecretProviderErrors() {
	cases := []struct {
		name     string
		svcErr   *tidcommon.ServiceError
		expected string
	}{
		{name: "rejected", svcErr: &tidcommon.ServiceError{Type: tidcommon.ClientErrorType, Code: "invalid"},
			expected: constants.ErrorInvalidGrant},
		{name: "provider failure", svcErr: &tidcommon.ServiceError{Type: tidcommon.ServerErrorType, Code: "boom"},
			expected: constants.ErrorServerError},
	}
	for _, tc := range cases {
		ts.Run(tc.name, func() {
			ts.SetupTest()
			ts.jwtService.EXPECT().VerifyJWTSignature(mock.Anything, mock.Anything).Return(nil)
			ts.deviceSecret.EXPECT().ValidateDeviceSecret(mock.Anything, mock.Anything, mock.Anything).
				Return(nil, tc.svcErr)
			_, errResp := ts.handler.HandleGrant(dpopCtx(nativeSSODeviceKey), ts.request("openid", ts.idToken(nil)),
				ts.childApp)
			ts.Require().NotNil(errResp)
			ts.Equal(tc.expected, errResp.Error)
		})
	}
}

func (ts *NativeSSOTestSuite) TestRejectsBindingMismatches() {
	cases := []struct {
		name  string
		jkt   string
		token string
	}{
		{name: "DPoP key is not the device key", jkt: "jkt-attacker", token: ts.idToken(nil)},
		{name: "ds_hash of another device secret", jkt: nativeSSODeviceKey,
			token: ts.idToken(map[string]interface{}{constants.ClaimDeviceSecretHash: deviceSecretHash("other")})},
		{name: "ID token of another session", jkt: nativeSSODeviceKey,
			token: ts.idToken(map[string]interface{}{constants.ClaimSessionID: "sid-2"})},
		{name: "ID token of another user", jkt: nativeSSODeviceKey,
			token: ts.idToken(map[string]interface{}{constants.ClaimSub: "someone-else"})},
		{name: "ID token not issued to the original client", jkt: nativeSSODeviceKey,
			token: ts.idToken(map[string]interface{}{constants.ClaimAud: "another-app"})},
	}
	for _, tc := range cases {
		ts.Run(tc.name, func() {
			ts.SetupTest()
			ts.expectValidCredentials()
			_, errResp := ts.handler.HandleGrant(dpopCtx(tc.jkt), ts.request("openid", tc.token), ts.childApp)
			ts.Require().NotNil(errResp)
			ts.Equal(constants.ErrorInvalidGrant, errResp.Error)
		})
	}
}

func (ts *NativeSSOTestSuite) TestRejectsWhenOriginalClientLostDeviceSSO() {
	ts.expectValidCredentials()
	ts.superApp.Scopes = []string{"openid", "profile"}
	ts.actors.EXPECT().GetOAuthClientByClientID(mock.Anything, nativeSSOSuperApp).Return(ts.superApp, nil)

	_, errResp := ts.handler.HandleGrant(dpopCtx(nativeSSODeviceKey), ts.request("openid", ts.idToken(nil)),
		ts.childApp)
	ts.Require().NotNil(errResp)
	ts.Equal(constants.ErrorInvalidGrant, errResp.Error)
}

func (ts *NativeSSOTestSuite) TestEnforcesScopeRules() {
	cases := []struct {
		name  string
		scope string
	}{
		{name: "scope not granted to the original client", scope: "openid phone"},
		{name: "scope not allowed for the requesting client", scope: "openid profile email address"},
		{name: "missing openid", scope: "profile"},
	}
	for _, tc := range cases {
		ts.Run(tc.name, func() {
			ts.SetupTest()
			ts.dsClaims.Scopes = append(ts.dsClaims.Scopes, "address")
			ts.expectValidCredentials()
			ts.actors.EXPECT().GetOAuthClientByClientID(mock.Anything, nativeSSOSuperApp).Return(ts.superApp, nil)
			_, errResp := ts.handler.HandleGrant(dpopCtx(nativeSSODeviceKey), ts.request(tc.scope, ts.idToken(nil)),
				ts.childApp)
			ts.Require().NotNil(errResp)
			ts.Equal(constants.ErrorInvalidScope, errResp.Error)
		})
	}
}

func (ts *NativeSSOTestSuite) TestRequiresInteractionWhenConsentNotCovered() {
	ts.expectValidCredentials()
	ts.actors.EXPECT().GetOAuthClientByClientID(mock.Anything, nativeSSOSuperApp).Return(ts.superApp, nil)
	ts.consent.EXPECT().ResolveNativeSSOConsent(mock.Anything, mock.Anything).
		Return(&providers.NativeSSOConsentResult{MissingScopes: []string{"email"}}, nil)

	_, errResp := ts.handler.HandleGrant(dpopCtx(nativeSSODeviceKey), ts.request("openid email", ts.idToken(nil)),
		ts.childApp)
	ts.Require().NotNil(errResp)
	ts.Equal(constants.ErrorInteractionRequired, errResp.Error)
	ts.Contains(errResp.ErrorDescription, "email")
}

func (ts *NativeSSOTestSuite) TestRequiresInteractionWithoutConsentProvider() {
	ts.handler.nativeSSO.Consent = nil
	ts.expectValidCredentials()
	ts.actors.EXPECT().GetOAuthClientByClientID(mock.Anything, nativeSSOSuperApp).Return(ts.superApp, nil)

	_, errResp := ts.handler.HandleGrant(dpopCtx(nativeSSODeviceKey), ts.request("openid", ts.idToken(nil)),
		ts.childApp)
	ts.Require().NotNil(errResp)
	ts.Equal(constants.ErrorInteractionRequired, errResp.Error)
}

func (ts *NativeSSOTestSuite) TestReplayIsRejectedBeforeConsentIsRecorded() {
	ts.expectValidCredentials()
	ts.actors.EXPECT().GetOAuthClientByClientID(mock.Anything, nativeSSOSuperApp).Return(ts.superApp, nil)
	ts.consent.EXPECT().ResolveNativeSSOConsent(mock.Anything, mock.Anything).
		Return(&providers.NativeSSOConsentResult{Covered: true}, nil)
	ts.deviceSecret.EXPECT().MarkDeviceSecretUsed(mock.Anything, mock.Anything, mock.Anything).
		Return(&tidcommon.ServiceError{Type: tidcommon.ClientErrorType, Code: "device_secret_already_redeemed"})

	_, errResp := ts.handler.HandleGrant(dpopCtx(nativeSSODeviceKey), ts.request("openid", ts.idToken(nil)),
		ts.childApp)
	ts.Require().NotNil(errResp)
	ts.Equal(constants.ErrorInvalidGrant, errResp.Error)
	ts.consent.AssertNotCalled(ts.T(), "RecordNativeSSOConsent", mock.Anything, mock.Anything)
}

func (ts *NativeSSOTestSuite) TestValidateGrantNativeSSOShape() {
	cases := []struct {
		name     string
		mutate   func(*model.TokenRequest)
		expected string
	}{
		{name: "valid", mutate: func(*model.TokenRequest) {}},
		{name: "device secret as subject token", expected: constants.ErrorInvalidRequest,
			mutate: func(r *model.TokenRequest) {
				r.SubjectTokenType = string(constants.TokenTypeIdentifierDeviceSecret)
			}},
		{name: "subject token is not an ID token", expected: constants.ErrorInvalidRequest,
			mutate: func(r *model.TokenRequest) {
				r.SubjectTokenType = string(constants.TokenTypeIdentifierAccessToken)
			}},
		{name: "non access token requested", expected: constants.ErrorInvalidRequest,
			mutate: func(r *model.TokenRequest) { r.RequestedTokenType = string(constants.TokenTypeIdentifierJWT) }},
		{name: "device_sso requested", expected: constants.ErrorInvalidScope,
			mutate: func(r *model.TokenRequest) { r.Scope = "openid device_sso" }},
	}
	for _, tc := range cases {
		ts.Run(tc.name, func() {
			req := ts.request("openid", ts.idToken(nil))
			tc.mutate(req)
			errResp := ts.handler.ValidateGrant(context.Background(), req, ts.childApp)
			if tc.expected == "" {
				ts.Nil(errResp)
				return
			}
			ts.Require().NotNil(errResp)
			ts.Equal(tc.expected, errResp.Error)
		})
	}
}

func (ts *NativeSSOTestSuite) TestDeviceSecretHashIsLeftHalfOfSHA256() {
	sum := sha256.Sum256([]byte("device-secret"))
	ts.Equal(base64.RawURLEncoding.EncodeToString(sum[:16]), deviceSecretHash("device-secret"))
}

func (ts *NativeSSOTestSuite) TestSplitDeviceSSOScope() {
	scopes, found := splitDeviceSSOScope([]string{"openid", constants.ScopeDeviceSSO, "profile"})
	ts.True(found)
	ts.Equal([]string{"openid", "profile"}, scopes)

	scopes, found = splitDeviceSSOScope([]string{"openid"})
	ts.False(found)
	ts.Equal([]string{"openid"}, scopes)
}

func (ts *NativeSSOTestSuite) TestValidateDeviceSSORequest() {
	cases := []struct {
		name      string
		nativeSSO NativeSSODependencies
		app       *providers.OAuthClient
		scopes    []string
		ctx       context.Context
		expected  string
	}{
		{name: "allowed", nativeSSO: NativeSSODependencies{DeviceSecret: ts.deviceSecret}, app: ts.superApp,
			scopes: []string{"openid"}, ctx: dpopCtx(nativeSSODeviceKey)},
		{name: "native SSO disabled", app: ts.superApp, scopes: []string{"openid"},
			ctx: dpopCtx(nativeSSODeviceKey), expected: constants.ErrorInvalidScope},
		{name: "client not registered for device_sso", nativeSSO: NativeSSODependencies{DeviceSecret: ts.deviceSecret},
			app: ts.childApp, scopes: []string{"openid"}, ctx: dpopCtx(nativeSSODeviceKey),
			expected: constants.ErrorInvalidScope},
		{name: "not an OpenID Connect request", nativeSSO: NativeSSODependencies{DeviceSecret: ts.deviceSecret},
			app: ts.superApp, scopes: []string{"profile"}, ctx: dpopCtx(nativeSSODeviceKey),
			expected: constants.ErrorInvalidScope},
		{name: "no DPoP proof to bind to", nativeSSO: NativeSSODependencies{DeviceSecret: ts.deviceSecret},
			app: ts.superApp, scopes: []string{"openid"}, ctx: context.Background(),
			expected: constants.ErrorInvalidDPoPProof},
		{name: "encrypted ID tokens", nativeSSO: NativeSSODependencies{DeviceSecret: ts.deviceSecret},
			app: &providers.OAuthClient{Scopes: ts.superApp.Scopes, Token: &providers.OAuthTokenConfig{
				IDToken: &providers.IDTokenConfig{ResponseType: providers.IDTokenResponseTypeJWE}}},
			scopes: []string{"openid"}, ctx: dpopCtx(nativeSSODeviceKey), expected: constants.ErrorInvalidScope},
	}
	for _, tc := range cases {
		ts.Run(tc.name, func() {
			errResp := validateDeviceSSORequest(tc.ctx, tc.nativeSSO, tc.app, tc.scopes)
			if tc.expected == "" {
				ts.Nil(errResp)
				return
			}
			ts.Require().NotNil(errResp)
			ts.Equal(tc.expected, errResp.Error)
		})
	}
}

func (ts *NativeSSOTestSuite) TestIssueDeviceSecretBindsIDTokenAndExtendsAttributes() {
	attrCache := attributecachemock.NewAttributeCacheServiceInterfaceMock(ts.T())
	expiresAt := time.Now().Add(24 * time.Hour)
	ts.deviceSecret.EXPECT().GenerateDeviceSecret(mock.Anything, mock.MatchedBy(
		func(r *providers.DeviceSecretRequest) bool {
			return r.Subject == nativeSSOSubject && r.AuthID == "code-id" && r.ClientID == nativeSSOSuperApp &&
				r.CnfJkt == nativeSSODeviceKey && r.AttributeCacheID == "aci-1" && r.ACR == "acr-otp" &&
				len(r.Scopes) == 2
		})).Return(&providers.DeviceSecret{Value: nativeSSODeviceSecret, ExpiresAt: expiresAt}, nil)
	attrCache.EXPECT().ExtendAttributeCacheTTL(mock.Anything, "aci-1", mock.MatchedBy(
		func(ttl int) bool { return ttl > 23*60*60 })).Return(nil)

	ds, claims, errResp := issueDeviceSecret(dpopCtx(nativeSSODeviceKey),
		NativeSSODependencies{DeviceSecret: ts.deviceSecret}, attrCache, &authz.AuthorizationCode{
			CodeID: "code-id", AuthorizedUserID: nativeSSOSubject, AttributeCacheID: "aci-1",
			CompletedACR: "acr-otp", TimeCreated: time.Now(),
		}, nativeSSOSuperApp, []string{"openid", "profile"})

	ts.Require().Nil(errResp)
	ts.Equal(nativeSSODeviceSecret, ds.Value)
	ts.Equal(deviceSecretHash(nativeSSODeviceSecret), claims[constants.ClaimDeviceSecretHash])
	ts.Equal("code-id", claims[constants.ClaimSessionID])
}

func (ts *NativeSSOTestSuite) TestIssueDeviceSecretFailsClosed() {
	ts.deviceSecret.EXPECT().GenerateDeviceSecret(mock.Anything, mock.Anything).
		Return(nil, &tidcommon.ServiceError{Type: tidcommon.ServerErrorType, Code: "boom"})

	_, _, errResp := issueDeviceSecret(dpopCtx(nativeSSODeviceKey), NativeSSODependencies{DeviceSecret: ts.deviceSecret},
		nil, &authz.AuthorizationCode{CodeID: "code-id", AuthorizedUserID: nativeSSOSubject}, nativeSSOSuperApp,
		[]string{"openid"})
	ts.Require().NotNil(errResp)
	ts.Equal(constants.ErrorServerError, errResp.Error)
}

func (ts *NativeSSOTestSuite) TestSessionEnforcement() {
	sessionToken := revocation.RevocationIdentity{JTI: "at-1", Criteria: []revocation.Criterion{
		{Type: revocation.CriterionTypeTokenFamily, Value: nativeSSOTokenFamilyPrefix + nativeSSOSessionID},
		{Type: revocation.CriterionTypeSubject, Value: nativeSSOSubject},
	}}
	otherToken := revocation.RevocationIdentity{JTI: "at-2", Criteria: []revocation.Criterion{
		{Type: revocation.CriterionTypeTokenFamily, Value: "tfid-of-a-normal-login"},
	}}

	ts.Run("disabled leaves enforcement untouched", func() {
		ts.Nil(NewNativeSSOEnforcement(nil, NativeSSODependencies{}))
	})
	ts.Run("ended session revokes its tokens", func() {
		ts.SetupTest()
		ts.deviceSecret.EXPECT().IsSessionActive(mock.Anything, nativeSSOSessionID).Return(false, nil)
		err := NewNativeSSOEnforcement(nil, ts.handler.nativeSSO).EnsureNotRevoked(context.Background(), sessionToken)
		ts.ErrorIs(err, revocation.ErrTokenRevoked)
	})
	ts.Run("live session defers to the next enforcement", func() {
		ts.SetupTest()
		ts.deviceSecret.EXPECT().IsSessionActive(mock.Anything, nativeSSOSessionID).Return(true, nil)
		next := &stubEnforcement{err: revocation.ErrTokenRevoked}
		err := NewNativeSSOEnforcement(next, ts.handler.nativeSSO).EnsureNotRevoked(context.Background(), sessionToken)
		ts.ErrorIs(err, revocation.ErrTokenRevoked)
		ts.True(next.called)
	})
	ts.Run("session store failure fails closed", func() {
		ts.SetupTest()
		ts.deviceSecret.EXPECT().IsSessionActive(mock.Anything, nativeSSOSessionID).
			Return(false, &tidcommon.ServiceError{Type: tidcommon.ServerErrorType})
		err := NewNativeSSOEnforcement(nil, ts.handler.nativeSSO).EnsureNotRevoked(context.Background(), sessionToken)
		ts.ErrorIs(err, revocation.ErrEnforcementUnavailable)
	})
	ts.Run("other tokens are not checked against SSO sessions", func() {
		ts.SetupTest()
		ts.Nil(NewNativeSSOEnforcement(nil, ts.handler.nativeSSO).EnsureNotRevoked(context.Background(), otherToken))
	})
}

type stubEnforcement struct {
	err    error
	called bool
}

func (s *stubEnforcement) EnsureNotRevoked(context.Context, revocation.RevocationIdentity) error {
	s.called = true
	return s.err
}
