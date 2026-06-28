package webpki

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// cloudflareRecordManager manages public A records through the Cloudflare API v4.
// Only a handful of endpoints are needed (find the zone, list/create/delete A
// records), so it speaks the REST API directly rather than pulling in a full SDK
// — lego's cloudflare client is internal and TXT-only. The token needs Zone:Read
// + DNS:Edit on the managed zone, the same scope DNS-01 uses.
type cloudflareRecordManager struct {
	token   string
	baseURL string
	http    *http.Client
	ttl     int
}

const cloudflareDefaultBaseURL = "https://api.cloudflare.com/client/v4"

func newCloudflareRecordManager(cfg CloudflareConfig) (*cloudflareRecordManager, error) {
	if cfg.APIToken == "" {
		return nil, fmt.Errorf("webpki: cloudflare A-record management requires api_token")
	}
	base := cfg.BaseURL
	if base == "" {
		base = cloudflareDefaultBaseURL
	}
	return &cloudflareRecordManager{
		token:   cfg.APIToken,
		baseURL: strings.TrimRight(base, "/"),
		http:    &http.Client{Timeout: 30 * time.Second},
		ttl:     60, // short, so funnel drain/failover propagates quickly
	}, nil
}

type cfAPIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type cfEnvelope struct {
	Success bool            `json:"success"`
	Errors  []cfAPIError    `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
}

func (c *cloudflareRecordManager) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env cfEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("cloudflare %s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if !env.Success {
		return fmt.Errorf("cloudflare %s %s: %v", method, path, env.Errors)
	}
	if out != nil && len(env.Result) > 0 {
		return json.Unmarshal(env.Result, out)
	}
	return nil
}

// zoneID finds the accessible zone that is the longest suffix of fqdn.
func (c *cloudflareRecordManager) zoneID(ctx context.Context, fqdn string) (string, error) {
	var zones []cfZone
	if err := c.do(ctx, http.MethodGet, "/zones?per_page=50", nil, &zones); err != nil {
		return "", err
	}
	var best cfZone
	for _, z := range zones {
		if (fqdn == z.Name || strings.HasSuffix(fqdn, "."+z.Name)) && len(z.Name) > len(best.Name) {
			best = z
		}
	}
	if best.ID == "" {
		return "", fmt.Errorf("cloudflare: no accessible zone for %q", fqdn)
	}
	return best.ID, nil
}

func (c *cloudflareRecordManager) listA(ctx context.Context, zoneID, fqdn string) ([]cfDNSRecord, error) {
	var recs []cfDNSRecord
	err := c.do(ctx, http.MethodGet, "/zones/"+zoneID+"/dns_records?type=A&name="+fqdn+"&per_page=100", nil, &recs)
	return recs, err
}

// SetA reconciles fqdn's A-record set to exactly ips, creating the missing and
// deleting the extra (leaving matching records untouched, so an unchanged record
// never has a no-resolution window during a partial change).
func (c *cloudflareRecordManager) SetA(ctx context.Context, fqdn string, ips []string) error {
	zoneID, err := c.zoneID(ctx, fqdn)
	if err != nil {
		return err
	}
	existing, err := c.listA(ctx, zoneID, fqdn)
	if err != nil {
		return err
	}
	have := make(map[string]string, len(existing)) // ip -> record id
	for _, r := range existing {
		have[r.Content] = r.ID
	}
	want := make(map[string]bool, len(ips))
	for _, ip := range ips {
		want[ip] = true
		if _, ok := have[ip]; ok {
			continue
		}
		if err := c.do(ctx, http.MethodPost, "/zones/"+zoneID+"/dns_records", map[string]any{
			"type": "A", "name": fqdn, "content": ip, "ttl": c.ttl, "proxied": false,
		}, nil); err != nil {
			return err
		}
	}
	for ip, id := range have {
		if want[ip] {
			continue
		}
		if err := c.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+id, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

func (c *cloudflareRecordManager) RemoveA(ctx context.Context, fqdn string) error {
	zoneID, err := c.zoneID(ctx, fqdn)
	if err != nil {
		return err
	}
	existing, err := c.listA(ctx, zoneID, fqdn)
	if err != nil {
		return err
	}
	for _, r := range existing {
		if err := c.do(ctx, http.MethodDelete, "/zones/"+zoneID+"/dns_records/"+r.ID, nil, nil); err != nil {
			return err
		}
	}
	return nil
}
