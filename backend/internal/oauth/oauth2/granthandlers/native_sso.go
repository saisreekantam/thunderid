// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package granthandlers

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/thunder-id/thunderid/internal/attributecache"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/authz"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/constants"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/dpop"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/model"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/resourceindicators"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/revocation"
	"github.com/thunder-id/thunderid/internal/oauth/oauth2/tokenservice"
	oauth2utils "github.com/thunder-id/thunderid/internal/oauth/oauth2/utils"
	"github.com/thunder-id/thunderid/internal/system/jose/jwt"
	"github.com/thunder-id/thunderid/internal/system/log"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/common"
	"github.com/thunder-id/thunderid/pkg/thunderidengine/providers"
)

// nativeSSOTokenFamilyPrefix marks the token family (tfid) of access tokens issued through Native
// SSO; the rest of the tfid is the SSO session id, so the tokens die with their session.
const nativeSSOTokenFamilyPrefix = "native-sso:"

// NativeSSODependencies carries the providers that enable OpenID Connect Native SSO for Mobile
// Apps 1.0. Native SSO is disabled when DeviceSecret is nil.
type NativeSSODependencies struct {
	DeviceSecret providers.DeviceSecretProvider
	Consent      providers.NativeSSOConsentProvider
}

// enabled reports whether Native SSO is configured.
func (d NativeSSODependencies) enabled() bool {
	return d.DeviceSecret != nil
}

// deviceSecretHash computes the ds_hash ID token claim: the base64url encoding of the left-most
// half of the SHA-256 hash of the device_secret, mirroring at_hash for the 256-bit signing
// algorithms ID tokens are signed with.
func deviceSecretHash(deviceSecret string) string {
	sum := sha256.Sum256([]byte(deviceSecret))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// splitDeviceSSOScope removes the device_sso protocol scope from scopes and reports whether it was
// present.
func splitDeviceSSOScope(scopes []string) ([]string, bool) {
	if !slices.Contains(scopes, constants.ScopeDeviceSSO) {
		return scopes, false
	}
	return slices.DeleteFunc(slices.Clone(scopes), func(s string) bool {
		return s == constants.ScopeDeviceSSO
	}), true
}

// validateDeviceSSORequest enforces the preconditions for issuing a device_secret on the
// authorization code grant: Native SSO is enabled, the client is registered for device_sso, the
// request is an OpenID Connect request, the token request carries a DPoP proof the device secret
// can be bound to, and the ID token is signed but not encrypted, so another app of the same vendor
// can present it to the token endpoint.
func validateDeviceSSORequest(ctx context.Context, nativeSSO NativeSSODependencies,
	oauthApp *providers.OAuthClient, scopes []string) *model.ErrorResponse {
	if !nativeSSO.enabled() {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidScope,
			ErrorDescription: "The device_sso scope is not supported",
		}
	}
	if !slices.Contains(oauthApp.Scopes, constants.ScopeDeviceSSO) {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidScope,
			ErrorDescription: "The client is not allowed to request the device_sso scope",
		}
	}
	if !slices.Contains(scopes, constants.ScopeOpenID) {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidScope,
			ErrorDescription: "The device_sso scope requires the openid scope",
		}
	}
	if dpop.GetJkt(ctx) == "" {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidDPoPProof,
			ErrorDescription: "A DPoP proof is required to bind the device_secret",
		}
	}
	if oauthApp.Token != nil && oauthApp.Token.IDToken != nil {
		rt := oauthApp.Token.IDToken.ResponseType
		if rt == providers.IDTokenResponseTypeJWE || rt == providers.IDTokenResponseTypeNESTEDJWT {
			return &model.ErrorResponse{
				Error:            constants.ErrorInvalidScope,
				ErrorDescription: "The device_sso scope requires signed, unencrypted ID tokens",
			}
		}
	}
	return nil
}

// issueDeviceSecret mints the device_secret for an authorization code grant that was granted the
// device_sso scope, keeps the login's attribute cache alive for the device secret's lifetime and
// returns the ID token claims that bind the ID token to the device secret (ds_hash, sid).
func issueDeviceSecret(ctx context.Context, nativeSSO NativeSSODependencies,
	attrCache attributecache.AttributeCacheServiceInterface, authCode *authz.AuthorizationCode,
	clientID string, scopes []string) (*providers.DeviceSecret, map[string]interface{}, *model.ErrorResponse) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "NativeSSO"))

	var claims map[string]interface{}
	if authCode.ClaimsRequest != nil {
		raw, err := json.Marshal(authCode.ClaimsRequest)
		if err == nil {
			err = json.Unmarshal(raw, &claims)
		}
		if err != nil {
			logger.Error(ctx, "Failed to encode the claims request for the device secret", log.Error(err))
			return nil, nil, &model.ErrorResponse{
				Error:            constants.ErrorServerError,
				ErrorDescription: "Failed to generate device secret",
			}
		}
	}

	deviceSecret, svcErr := nativeSSO.DeviceSecret.GenerateDeviceSecret(ctx, &providers.DeviceSecretRequest{
		Subject:          authCode.AuthorizedUserID,
		AuthID:           authCode.CodeID,
		ClientID:         clientID,
		Scopes:           scopes,
		ACR:              authCode.CompletedACR,
		Claims:           claims,
		CnfJkt:           dpop.GetJkt(ctx),
		AttributeCacheID: authCode.AttributeCacheID,
		AuthTime:         authCode.TimeCreated.Unix(),
	})
	if svcErr != nil || deviceSecret == nil || deviceSecret.Value == "" {
		logger.Error(ctx, "Failed to generate device secret", log.Any("error", svcErr))
		return nil, nil, &model.ErrorResponse{
			Error:            constants.ErrorServerError,
			ErrorDescription: "Failed to generate device secret",
		}
	}

	// Apps signing in through Native SSO are served the attributes resolved during this login, so
	// they must outlive the login's own tokens for as long as the device secret is valid.
	if authCode.AttributeCacheID != "" && attrCache != nil {
		ttl := int(time.Until(deviceSecret.ExpiresAt).Seconds())
		if ttl > 0 {
			if cacheErr := attrCache.ExtendAttributeCacheTTL(ctx, authCode.AttributeCacheID, ttl); cacheErr != nil {
				logger.Error(ctx, "Failed to extend the attribute cache for the device secret",
					log.String("error", cacheErr.Error.DefaultValue))
				return nil, nil, &model.ErrorResponse{
					Error:            constants.ErrorServerError,
					ErrorDescription: "Failed to generate device secret",
				}
			}
		}
	}

	return deviceSecret, map[string]interface{}{
		constants.ClaimDeviceSecretHash: deviceSecretHash(deviceSecret.Value),
		constants.ClaimSessionID:        authCode.CodeID,
	}, nil
}

// validateNativeSSOExchangeRequest validates the shape of a Native SSO token exchange request
// (actor_token_type is the device-secret token type).
func validateNativeSSOExchangeRequest(tokenRequest *model.TokenRequest) *model.ErrorResponse {
	if constants.TokenTypeIdentifier(tokenRequest.SubjectTokenType) != constants.TokenTypeIdentifierIDToken {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidRequest,
			ErrorDescription: "Native SSO requires subject_token_type urn:ietf:params:oauth:token-type:id_token",
		}
	}
	if tokenRequest.RequestedTokenType != "" &&
		constants.TokenTypeIdentifier(tokenRequest.RequestedTokenType) != constants.TokenTypeIdentifierAccessToken {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidRequest,
			ErrorDescription: "Native SSO only issues access tokens",
		}
	}
	if slices.Contains(tokenservice.ParseScopes(tokenRequest.Scope), constants.ScopeDeviceSSO) {
		return &model.ErrorResponse{
			Error:            constants.ErrorInvalidScope,
			ErrorDescription: "The device_sso scope cannot be requested on token exchange",
		}
	}
	return nil
}

// nativeSSOIDTokenClaims are the subject_token (ID token) claims Native SSO depends on.
type nativeSSOIDTokenClaims struct {
	sub    string
	sid    string
	dsHash string
	aud    []string
}

// handleNativeSSOGrant performs the OpenID Connect Native SSO for Mobile Apps 1.0 token exchange: a
// second app of the same vendor presents the first app's ID token as subject_token and its
// device_secret as actor_token, with a DPoP proof signed by the device key the device secret is
// bound to, and receives its own DPoP-bound access token without the user signing in again.
func (h *tokenExchangeGrantHandler) handleNativeSSOGrant(ctx context.Context, tokenRequest *model.TokenRequest,
	oauthApp *providers.OAuthClient) (*model.TokenResponseDTO, *model.ErrorResponse) {
	logger := log.GetLogger().With(log.String(log.LoggerKeyComponentName, "NativeSSO"),
		log.String("client_id", tokenRequest.ClientID))

	if !h.nativeSSO.enabled() {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorUnsupportedTokenType,
			ErrorDescription: "Native SSO is not enabled",
		}
	}

	// The device secret is bound to the device key; the exchange must prove possession of it.
	jkt := dpop.GetJkt(ctx)
	if jkt == "" {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidDPoPProof,
			ErrorDescription: "A DPoP proof is required for Native SSO",
		}
	}

	idClaims, errResp := h.verifyNativeSSOIDToken(ctx, tokenRequest.SubjectToken)
	if errResp != nil {
		return nil, errResp
	}

	dsClaims, svcErr := h.nativeSSO.DeviceSecret.ValidateDeviceSecret(ctx, tokenRequest.ClientID,
		tokenRequest.ActorToken)
	if svcErr != nil {
		return nil, nativeSSOProviderError(ctx, logger, svcErr, "Invalid actor_token")
	}
	if dsClaims == nil {
		return nil, &model.ErrorResponse{Error: constants.ErrorInvalidGrant, ErrorDescription: "Invalid actor_token"}
	}

	// The DPoP key must be the exact key the device secret was bound to at login.
	if subtle.ConstantTimeCompare([]byte(jkt), []byte(dsClaims.CnfJkt)) != 1 {
		logger.Debug(ctx, "DPoP key does not match the device secret binding")
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidGrant,
			ErrorDescription: "The DPoP proof key does not match the device_secret binding",
		}
	}

	// The ID token must have been issued together with this device secret.
	if subtle.ConstantTimeCompare([]byte(deviceSecretHash(tokenRequest.ActorToken)), []byte(idClaims.dsHash)) != 1 {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidGrant,
			ErrorDescription: "The subject_token is not bound to the device_secret",
		}
	}
	if idClaims.sid != dsClaims.SessionID || idClaims.sub != dsClaims.Subject ||
		!slices.Contains(idClaims.aud, dsClaims.ClientID) {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidGrant,
			ErrorDescription: "The subject_token does not belong to the device_secret session",
		}
	}

	// The client the device secret was minted for must still be registered for device_sso.
	origApp, svcErr := h.actorProvider.GetOAuthClientByClientID(ctx, dsClaims.ClientID)
	if svcErr != nil {
		return nil, nativeSSOProviderError(ctx, logger, svcErr, "Invalid actor_token")
	}
	if origApp == nil || !slices.Contains(origApp.Scopes, constants.ScopeDeviceSSO) {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidGrant,
			ErrorDescription: "The device_secret was not issued to a client allowed to use device_sso",
		}
	}

	finalScopes, errResp := nativeSSOScopes(tokenRequest, dsClaims, oauthApp)
	if errResp != nil {
		return nil, errResp
	}

	consentReq := &providers.NativeSSOConsentRequest{
		Subject:          dsClaims.Subject,
		ClientID:         tokenRequest.ClientID,
		OriginalClientID: dsClaims.ClientID,
		RequestedScopes:  finalScopes,
		SessionID:        dsClaims.SessionID,
	}
	releasableClaims, errResp := h.resolveNativeSSOConsent(ctx, logger, consentReq)
	if errResp != nil {
		return nil, errResp
	}

	if svcErr := h.nativeSSO.DeviceSecret.MarkDeviceSecretUsed(ctx, dsClaims, tokenRequest.ClientID); svcErr != nil {
		return nil, nativeSSOProviderError(ctx, logger, svcErr, "The device_secret cannot be redeemed")
	}

	// The original client is served its own login attributes; any other client gets a copy holding
	// only the claims its consent covers, so it never sees what was released to the original client.
	attributeCacheID := dsClaims.AttributeCacheID
	if consentReq.ClientID != consentReq.OriginalClientID {
		attributeCacheID, errResp = h.deriveNativeSSOAttributes(ctx, logger, dsClaims.AttributeCacheID,
			releasableClaims, oauthApp)
		if errResp != nil {
			return nil, errResp
		}
	}

	accessToken, errResp := h.buildNativeSSOAccessToken(ctx, tokenRequest, oauthApp, dsClaims, finalScopes, jkt,
		attributeCacheID)
	if errResp != nil {
		return nil, errResp
	}

	if h.nativeSSO.Consent != nil && consentReq.ClientID != consentReq.OriginalClientID {
		if svcErr := h.nativeSSO.Consent.RecordNativeSSOConsent(ctx, consentReq); svcErr != nil {
			return nil, nativeSSOProviderError(ctx, logger, svcErr, "Consent could not be recorded")
		}
	}

	logger.Debug(ctx, "Native SSO token exchange succeeded",
		log.String("original_client_id", dsClaims.ClientID))
	return &model.TokenResponseDTO{AccessToken: *accessToken}, nil
}

// verifyNativeSSOIDToken verifies that the subject_token is a signed ID token issued by this
// server and extracts the claims Native SSO depends on. Its exp is intentionally not enforced: the
// ID token may have expired while the SSO session it belongs to, governed by the device secret's
// lifetime, is still valid.
func (h *tokenExchangeGrantHandler) verifyNativeSSOIDToken(ctx context.Context,
	idToken string) (*nativeSSOIDTokenClaims, *model.ErrorResponse) {
	invalid := &model.ErrorResponse{
		Error:            constants.ErrorInvalidGrant,
		ErrorDescription: "Invalid subject_token",
	}
	if strings.Count(idToken, ".") != 2 {
		return nil, invalid
	}
	header, err := jwt.DecodeJWTHeader(idToken)
	if err != nil {
		return nil, invalid
	}
	if typ, _ := header["typ"].(string); typ != "" && !strings.EqualFold(typ, jwt.TokenTypeJWT) {
		return nil, invalid
	}
	if svcErr := h.jwtService.VerifyJWTSignature(ctx, idToken); svcErr != nil {
		return nil, invalid
	}
	claims, err := jwt.DecodeJWTPayload(idToken)
	if err != nil {
		return nil, invalid
	}
	if iss, _ := claims[constants.ClaimIss].(string); iss != h.cfg.JWT.Issuer {
		return nil, invalid
	}
	// A refresh token shares typ JWT with ID tokens but carries access_token_sub.
	if _, isRefreshToken := claims[constants.ClaimAccessTokenSubject]; isRefreshToken {
		return nil, invalid
	}

	result := &nativeSSOIDTokenClaims{}
	result.sub, _ = claims[constants.ClaimSub].(string)
	result.sid, _ = claims[constants.ClaimSessionID].(string)
	result.dsHash, _ = claims[constants.ClaimDeviceSecretHash].(string)
	switch aud := claims[constants.ClaimAud].(type) {
	case string:
		result.aud = []string{aud}
	case []interface{}:
		for _, a := range aud {
			if s, ok := a.(string); ok {
				result.aud = append(result.aud, s)
			}
		}
	}
	if result.sub == "" || result.sid == "" || result.dsHash == "" || len(result.aud) == 0 {
		return nil, invalid
	}
	return result, nil
}

// nativeSSOScopes resolves the scopes of the access token issued through Native SSO. They must be
// a subset of the scopes granted to the original client and allowed for the requesting client;
// unlike plain token exchange, scopes outside that set fail the request instead of being dropped.
func nativeSSOScopes(tokenRequest *model.TokenRequest, dsClaims *providers.DeviceSecretClaims,
	oauthApp *providers.OAuthClient) ([]string, *model.ErrorResponse) {
	requested := tokenservice.ParseScopes(tokenRequest.Scope)
	if len(requested) == 0 {
		requested = dsClaims.Scopes
	}

	var notGranted, notAllowed []string
	for _, s := range requested {
		if !slices.Contains(dsClaims.Scopes, s) {
			notGranted = append(notGranted, s)
			continue
		}
		if s != constants.ScopeOpenID && !slices.Contains(oauthApp.Scopes, s) {
			notAllowed = append(notAllowed, s)
		}
	}
	if len(notGranted) > 0 {
		return nil, &model.ErrorResponse{
			Error: constants.ErrorInvalidScope,
			ErrorDescription: "Requested scopes exceed the scopes granted to the original client: " +
				strings.Join(notGranted, " "),
		}
	}
	if len(notAllowed) > 0 {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidScope,
			ErrorDescription: "Requested scopes are not allowed for the client: " + strings.Join(notAllowed, " "),
		}
	}
	if !slices.Contains(requested, constants.ScopeOpenID) {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInvalidScope,
			ErrorDescription: "Native SSO requires the openid scope",
		}
	}
	return requested, nil
}

// resolveNativeSSOConsent checks that the consent given to the original client covers the
// requesting client's scopes and returns the claims the requesting client may receive. A client
// other than the original one cannot be signed in silently without a consent provider to vouch for
// it.
func (h *tokenExchangeGrantHandler) resolveNativeSSOConsent(ctx context.Context, logger *log.Logger,
	req *providers.NativeSSOConsentRequest) ([]string, *model.ErrorResponse) {
	if req.ClientID == req.OriginalClientID {
		return nil, nil
	}
	if h.nativeSSO.Consent == nil {
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorInteractionRequired,
			ErrorDescription: "User consent is required for this client",
		}
	}

	result, svcErr := h.nativeSSO.Consent.ResolveNativeSSOConsent(ctx, req)
	if svcErr != nil {
		return nil, nativeSSOProviderError(ctx, logger, svcErr, "Consent could not be resolved")
	}
	if result == nil || !result.Covered {
		description := "User consent is required for this client"
		if result != nil && len(result.MissingScopes) > 0 {
			description += ": " + strings.Join(result.MissingScopes, " ")
		}
		return nil, &model.ErrorResponse{Error: constants.ErrorInteractionRequired, ErrorDescription: description}
	}
	return result.ReleasableClaims, nil
}

// deriveNativeSSOAttributes creates the requesting client's own attribute cache from the login's
// attributes, keeping only the releasable claims. When the identity system returned its user
// record as an opaque signed JWT (issued to the original client), the claims are taken from its
// payload, which this server fetched itself, and re-released per client; an encrypted record
// cannot be narrowed, so the request falls back to an interactive login.
func (h *tokenExchangeGrantHandler) deriveNativeSSOAttributes(ctx context.Context, logger *log.Logger,
	attributeCacheID string, releasable []string, oauthApp *providers.OAuthClient) (string, *model.ErrorResponse) {
	if attributeCacheID == "" || len(releasable) == 0 {
		return "", nil
	}
	if h.attributeCache == nil {
		return "", &model.ErrorResponse{Error: constants.ErrorServerError, ErrorDescription: "Failed to generate token"}
	}

	original, svcErr := h.attributeCache.GetAttributeCache(ctx, attributeCacheID)
	if svcErr != nil || original == nil {
		logger.Debug(ctx, "Login attributes are no longer available for Native SSO")
		return "", &model.ErrorResponse{
			Error:            constants.ErrorInteractionRequired,
			ErrorDescription: "The user must sign in to this client",
		}
	}

	source := original.Attributes
	if raw, ok := original.Attributes[providers.RawJWTAttributeKey].(string); ok && raw != "" {
		if strings.Count(raw, ".") != 2 {
			return "", &model.ErrorResponse{
				Error:            constants.ErrorInteractionRequired,
				ErrorDescription: "The user's attributes cannot be shared with this client",
			}
		}
		payload, err := jwt.DecodeJWTPayload(raw)
		if err != nil {
			return "", &model.ErrorResponse{Error: constants.ErrorServerError, ErrorDescription: "Failed to generate token"}
		}
		source = payload
	}

	attributes := make(map[string]interface{}, len(releasable))
	for _, claim := range releasable {
		if v, ok := source[claim]; ok {
			attributes[claim] = v
		}
	}

	ttl := oauthApp.UserAccessTokenConfig().ValidityPeriodOrZero()
	if ttl <= 0 {
		ttl = h.cfg.JWT.ValidityPeriod
	}
	if ttl <= 0 {
		ttl = 3600
	}
	created, svcErr := h.attributeCache.CreateAttributeCache(ctx, &attributecache.AttributeCache{
		Attributes: attributes, TTLSeconds: ttl,
	})
	if svcErr != nil || created == nil {
		logger.Error(ctx, "Failed to create the Native SSO attribute cache")
		return "", &model.ErrorResponse{Error: constants.ErrorServerError, ErrorDescription: "Failed to generate token"}
	}
	return created.ID, nil
}

// buildNativeSSOAccessToken issues the requesting client's access token, bound to the same DPoP key
// as the device secret and serving the attributes the user consented to at login. The original
// client is recorded as the actor.
func (h *tokenExchangeGrantHandler) buildNativeSSOAccessToken(ctx context.Context, tokenRequest *model.TokenRequest,
	oauthApp *providers.OAuthClient, dsClaims *providers.DeviceSecretClaims, scopes []string,
	jkt, attributeCacheID string) (*model.TokenDTO, *model.ErrorResponse) {
	oidcScopes, permissionScopes := oauth2utils.SeparateOIDCAndNonOIDCScopes(
		tokenservice.JoinScopes(scopes), oauthApp.ScopeClaims)
	targetRS, errResp := resourceindicators.ResolveAudienceBinding(
		ctx, h.resourceService, tokenRequest.Resources, permissionScopes)
	if errResp != nil {
		return nil, errResp
	}

	finalScopes := oidcScopes
	audiences := []string{oauthApp.ResolveDefaultAudience(tokenRequest.ClientID)}
	if targetRS != nil {
		permissionScopes, errResp = resourceindicators.DownscopeToResourceServer(
			ctx, h.resourceService, targetRS.ID, permissionScopes)
		if errResp != nil {
			return nil, errResp
		}
		finalScopes = append(slices.Clone(oidcScopes), permissionScopes...)
		audiences = []string{targetRS.Identifier}
	}

	userSubConfig := oauthApp.UserAccessTokenConfig()
	accessToken, err := h.tokenBuilder.BuildAccessToken(ctx, &tokenservice.AccessTokenBuildContext{
		Subject:          dsClaims.Subject,
		Audiences:        audiences,
		ClientID:         tokenRequest.ClientID,
		Scopes:           finalScopes,
		AttributeCacheID: attributeCacheID,
		GrantType:        string(providers.GrantTypeTokenExchange),
		OAuthApp:         oauthApp,
		ActorClaims:      &tokenservice.SubjectTokenClaims{Sub: dsClaims.ClientID},
		ValidityPeriod:   userSubConfig.ValidityPeriodOrZero(),
		DPoPJkt:          jkt,
		TokenFamilyID:    nativeSSOTokenFamilyPrefix + dsClaims.SessionID,
	})
	if err != nil {
		log.GetLogger().Error(ctx, "Failed to generate Native SSO access token", log.Error(err))
		return nil, &model.ErrorResponse{
			Error:            constants.ErrorServerError,
			ErrorDescription: "Failed to generate token",
		}
	}
	return accessToken, nil
}

// nativeSSOProviderError maps a provider ServiceError to a token endpoint error: client errors
// reject the grant, anything else is a server error.
func nativeSSOProviderError(ctx context.Context, logger *log.Logger, svcErr *common.ServiceError,
	description string) *model.ErrorResponse {
	if svcErr.Type == common.ClientErrorType {
		logger.Debug(ctx, "Native SSO request rejected", log.String("code", svcErr.Code))
		return &model.ErrorResponse{Error: constants.ErrorInvalidGrant, ErrorDescription: description}
	}
	logger.Error(ctx, "Native SSO provider failed", log.String("code", svcErr.Code))
	return &model.ErrorResponse{Error: constants.ErrorServerError, ErrorDescription: "Failed to process token request"}
}

// nativeSSOSessionEnforcement rejects access tokens issued through Native SSO once their SSO session
// has ended, then defers to the configured revocation enforcement (if any) for everything else.
type nativeSSOSessionEnforcement struct {
	next     revocation.EnforcementServiceInterface
	sessions providers.DeviceSecretProvider
}

// NewNativeSSOEnforcement wraps the token revocation enforcement so Native SSO tokens are also
// checked against the liveness of their SSO session. It returns next unchanged when Native SSO is
// disabled.
func NewNativeSSOEnforcement(next revocation.EnforcementServiceInterface,
	nativeSSO NativeSSODependencies) revocation.EnforcementServiceInterface {
	if !nativeSSO.enabled() {
		return next
	}
	return &nativeSSOSessionEnforcement{next: next, sessions: nativeSSO.DeviceSecret}
}

// EnsureNotRevoked implements revocation.EnforcementServiceInterface.
func (e *nativeSSOSessionEnforcement) EnsureNotRevoked(ctx context.Context,
	identity revocation.RevocationIdentity) error {
	for _, criterion := range identity.Criteria {
		if criterion.Type != revocation.CriterionTypeTokenFamily ||
			!strings.HasPrefix(criterion.Value, nativeSSOTokenFamilyPrefix) {
			continue
		}
		active, svcErr := e.sessions.IsSessionActive(ctx,
			strings.TrimPrefix(criterion.Value, nativeSSOTokenFamilyPrefix))
		if svcErr != nil {
			return revocation.ErrEnforcementUnavailable
		}
		if !active {
			return revocation.ErrTokenRevoked
		}
	}
	if e.next != nil {
		return e.next.EnsureNotRevoked(ctx, identity)
	}
	return nil
}
