package controller

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Minimal OIDC ID-token verification built on stdlib crypto.
//
// coreos/go-oidc v3 depends on go-jose/v4, which is absent from this module's
// go.sum (and the spine go.mod must not change), so the controller verifies ID
// tokens itself: OIDC discovery -> JWKS fetch -> JWS signature check ->
// iss/aud/exp/nbf claim checks. Asymmetric algorithms only — "none" and HMAC
// are rejected outright (HMAC would let anyone holding the shared secret,
// i.e. any relying party, mint tokens).

const (
	oidcHTTPTimeout  = 10 * time.Second
	oidcMaxBody      = 1 << 20 // discovery/JWKS response cap
	oidcClockSkew    = 2 * time.Minute
	oidcJWKSCacheTTL = 5 * time.Minute
)

type oidcVerifier struct {
	issuer   string
	clientID string
	client   *http.Client

	mu        sync.Mutex
	jwksURI   string
	keys      []jwkKey
	fetchedAt time.Time
}

type jwkKey struct {
	kid string
	alg string
	use string
	pub crypto.PublicKey
}

func newOIDCVerifier(issuer, clientID string) *oidcVerifier {
	return &oidcVerifier{
		issuer:   issuer,
		clientID: clientID,
		client:   &http.Client{Timeout: oidcHTTPTimeout},
	}
}

func (v *oidcVerifier) getJSON(ctx context.Context, url string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, oidcMaxBody))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// discover resolves and caches jwks_uri. Lazy: called on first login so the
// controller starts even when the IdP is down.
func (v *oidcVerifier) discover(ctx context.Context) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.jwksURI != "" {
		return v.jwksURI, nil
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	wellKnown := strings.TrimSuffix(v.issuer, "/") + "/.well-known/openid-configuration"
	if err := v.getJSON(ctx, wellKnown, &doc); err != nil {
		return "", fmt.Errorf("oidc discovery: %w", err)
	}
	if doc.Issuer != v.issuer {
		return "", fmt.Errorf("oidc discovery: issuer mismatch: document says %q, configured %q", doc.Issuer, v.issuer)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("oidc discovery: no jwks_uri")
	}
	v.jwksURI = doc.JWKSURI
	return v.jwksURI, nil
}

type rawJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func parseJWK(j rawJWK) (jwkKey, error) {
	out := jwkKey{kid: j.Kid, alg: j.Alg, use: j.Use}
	switch j.Kty {
	case "RSA":
		nb, err := base64.RawURLEncoding.DecodeString(j.N)
		if err != nil {
			return out, fmt.Errorf("jwk n: %w", err)
		}
		eb, err := base64.RawURLEncoding.DecodeString(j.E)
		if err != nil {
			return out, fmt.Errorf("jwk e: %w", err)
		}
		e := new(big.Int).SetBytes(eb)
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31 {
			return out, fmt.Errorf("jwk: unreasonable RSA exponent")
		}
		out.pub = &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}
	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return out, fmt.Errorf("jwk: unsupported curve %q", j.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return out, fmt.Errorf("jwk x: %w", err)
		}
		yb, err := base64.RawURLEncoding.DecodeString(j.Y)
		if err != nil {
			return out, fmt.Errorf("jwk y: %w", err)
		}
		pub := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
		if !curve.IsOnCurve(pub.X, pub.Y) {
			return out, fmt.Errorf("jwk: EC point not on curve")
		}
		out.pub = pub
	default:
		return out, fmt.Errorf("jwk: unsupported kty %q", j.Kty)
	}
	return out, nil
}

// Warm pre-fetches discovery + JWKS so the first verify after startup is fast
// and cannot transiently 401. Best-effort; retries briefly since keycloak may
// still be coming up (hairpin) right when the controller restarts.
func (v *oidcVerifier) Warm(ctx context.Context) {
	for i := 0; i < 6; i++ {
		if _, err := v.signingKeys(ctx, ""); err == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// signingKeys returns the cached JWKS, refetching when stale or when the
// token names a kid we have not seen (key rotation).
func (v *oidcVerifier) signingKeys(ctx context.Context, wantKid string) ([]jwkKey, error) {
	jwksURI, err := v.discover(ctx)
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	fresh := time.Since(v.fetchedAt) < oidcJWKSCacheTTL
	if fresh && (wantKid == "" || v.hasKidLocked(wantKid)) {
		return v.keys, nil
	}
	var doc struct {
		Keys []rawJWK `json:"keys"`
	}
	if err := v.getJSON(ctx, jwksURI, &doc); err != nil {
		return nil, fmt.Errorf("jwks fetch: %w", err)
	}
	var keys []jwkKey
	for _, rk := range doc.Keys {
		if rk.Use != "" && rk.Use != "sig" {
			continue
		}
		k, err := parseJWK(rk)
		if err != nil {
			continue // skip unusable keys; verification fails closed anyway
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("jwks: no usable signing keys")
	}
	v.keys = keys
	v.fetchedAt = time.Now()
	return keys, nil
}

func (v *oidcVerifier) hasKidLocked(kid string) bool {
	for _, k := range v.keys {
		if k.kid == kid {
			return true
		}
	}
	return false
}

func jwsHash(alg string) (crypto.Hash, bool) {
	switch alg {
	case "RS256", "PS256", "ES256":
		return crypto.SHA256, true
	case "RS384", "PS384", "ES384":
		return crypto.SHA384, true
	case "RS512", "PS512", "ES512":
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

func verifyJWS(alg string, pub crypto.PublicKey, signingInput, sig []byte) error {
	hash, ok := jwsHash(alg)
	if !ok {
		return fmt.Errorf("unsupported or forbidden alg %q", alg)
	}
	var digest []byte
	switch hash {
	case crypto.SHA256:
		d := sha256.Sum256(signingInput)
		digest = d[:]
	case crypto.SHA384:
		d := sha512.Sum384(signingInput)
		digest = d[:]
	case crypto.SHA512:
		d := sha512.Sum512(signingInput)
		digest = d[:]
	}
	switch alg[:2] {
	case "RS":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("alg %s requires an RSA key", alg)
		}
		return rsa.VerifyPKCS1v15(rsaPub, hash, digest, sig)
	case "PS":
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("alg %s requires an RSA key", alg)
		}
		return rsa.VerifyPSS(rsaPub, hash, digest, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES":
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("alg %s requires an EC key", alg)
		}
		// JWS ECDSA signatures are raw r||s, fixed width per curve.
		byteLen := (ecPub.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*byteLen {
			return fmt.Errorf("ECDSA signature has wrong length")
		}
		r := new(big.Int).SetBytes(sig[:byteLen])
		s := new(big.Int).SetBytes(sig[byteLen:])
		if !ecdsa.Verify(ecPub, digest, r, s) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported alg %q", alg)
	}
}

// verify checks the raw ID token's signature and standard claims and returns
// the full claim set. Every failure is terminal — no fallback paths.
func (v *oidcVerifier) verify(ctx context.Context, rawToken string) (map[string]any, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("token is not a JWS compact serialization")
	}
	headerB, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("token header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerB, &header); err != nil {
		return nil, fmt.Errorf("token header: %w", err)
	}
	if _, ok := jwsHash(header.Alg); !ok {
		return nil, fmt.Errorf("unsupported or forbidden alg %q", header.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("token signature: %w", err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])

	keys, err := v.signingKeys(ctx, header.Kid)
	if err != nil {
		return nil, err
	}
	verified := false
	for _, k := range keys {
		if header.Kid != "" && k.kid != header.Kid {
			continue
		}
		if k.alg != "" && k.alg != header.Alg {
			continue
		}
		if verifyJWS(header.Alg, k.pub, signingInput, sig) == nil {
			verified = true
			break
		}
	}
	if !verified {
		return nil, fmt.Errorf("token signature verification failed")
	}

	payloadB, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("token payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadB, &claims); err != nil {
		return nil, fmt.Errorf("token claims: %w", err)
	}
	if err := v.checkClaims(claims, time.Now()); err != nil {
		return nil, err
	}
	return claims, nil
}

func (v *oidcVerifier) checkClaims(claims map[string]any, now time.Time) error {
	if iss, _ := claims["iss"].(string); iss != v.issuer {
		return fmt.Errorf("token issuer %q != %q", claims["iss"], v.issuer)
	}
	audOK := false
	switch aud := claims["aud"].(type) {
	case string:
		audOK = aud == v.clientID
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == v.clientID {
				audOK = true
			}
		}
	}
	if !audOK {
		return fmt.Errorf("token audience does not include %q", v.clientID)
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return fmt.Errorf("token has no exp claim")
	}
	if now.After(time.Unix(int64(exp), 0).Add(oidcClockSkew)) {
		return fmt.Errorf("token expired")
	}
	if nbf, ok := claims["nbf"].(float64); ok {
		if now.Add(oidcClockSkew).Before(time.Unix(int64(nbf), 0)) {
			return fmt.Errorf("token not yet valid")
		}
	}
	return nil
}
