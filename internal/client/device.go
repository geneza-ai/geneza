package client

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RFC 8628 device-grant client. The CLI captures its CSR up front, asks the
// controller for a device+user code, prints the verification URL + code for the
// human to approve in the web console, then polls until the controller returns the
// issued cert. All requests run over the pinned-CA HTTP client.

type DeviceAuth struct {
	DeviceCode              string `json:"deviceCode"`
	UserCode                string `json:"userCode"`
	VerificationURI         string `json:"verificationUri"`
	VerificationURIComplete string `json:"verificationUriComplete"`
	Interval                int    `json:"interval"`
	ExpiresIn               int    `json:"expiresIn"`
}

type DeviceCert struct {
	UserCertPEM []byte
	CARootsPEM  []byte
	ExpiresUnix int64
}

func httpPostJSON(ctx context.Context, c *http.Client, url string, body any) (int, []byte, error) {
	enc, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(enc))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBody))
	return resp.StatusCode, rb, err
}

// DeviceAuthorize starts a device login and returns the codes to show the human.
func DeviceAuthorize(ctx context.Context, controllerHTTP string, pool *x509.CertPool, csrPEM []byte, clientName string) (*DeviceAuth, error) {
	code, body, err := httpPostJSON(ctx, VerifiedHTTPClient(pool), controllerHTTP+"/v1/device/authorize",
		map[string]string{"csrPem": string(csrPEM), "clientName": clientName})
	if err != nil {
		return nil, fmt.Errorf("device authorize: %w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("device authorize: %s: %s", http.StatusText(code), truncate(string(body), 200))
	}
	var da DeviceAuth
	if err := json.Unmarshal(body, &da); err != nil {
		return nil, fmt.Errorf("device authorize response: %w", err)
	}
	return &da, nil
}

// DevicePoll polls the token endpoint until the human approves (returning the
// issued cert), denies, or the code expires. It honors the RFC 8628 slow_down.
func DevicePoll(ctx context.Context, controllerHTTP string, pool *x509.CertPool, da *DeviceAuth) (*DeviceCert, error) {
	client := VerifiedHTTPClient(pool)
	interval := da.Interval
	if interval < 1 {
		interval = 5
	}
	deadline := time.Now().Add(time.Duration(da.ExpiresIn) * time.Second)
	for {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("device login timed out; run `geneza login` again")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(interval) * time.Second):
		}
		code, body, err := httpPostJSON(ctx, client, controllerHTTP+"/v1/device/token",
			map[string]string{"deviceCode": da.DeviceCode})
		if err != nil {
			return nil, fmt.Errorf("device token: %w", err)
		}
		if code == http.StatusOK {
			var r struct {
				UserCertPEM string `json:"userCertPem"`
				CARootsPEM  string `json:"caRootsPem"`
				ExpiresUnix int64  `json:"expiresUnix"`
			}
			if err := json.Unmarshal(body, &r); err != nil {
				return nil, fmt.Errorf("device token response: %w", err)
			}
			return &DeviceCert{UserCertPEM: []byte(r.UserCertPEM), CARootsPEM: []byte(r.CARootsPEM), ExpiresUnix: r.ExpiresUnix}, nil
		}
		var er struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &er)
		switch er.Error {
		case "authorization_pending":
			// keep waiting
		case "slow_down":
			interval += 5
		case "access_denied":
			return nil, fmt.Errorf("device login was denied")
		case "expired_token":
			return nil, fmt.Errorf("device login expired; run `geneza login` again")
		default:
			return nil, fmt.Errorf("device token: %s: %s", http.StatusText(code), truncate(string(body), 200))
		}
	}
}
