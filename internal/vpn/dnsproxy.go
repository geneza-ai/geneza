package vpn

import (
	"context"
	"fmt"
	"net"
	"time"
)

// DNSStubAddr is the loopback address+port the local stub binds (distinct from
// systemd-resolved's own 127.0.0.53). The system resolver is pointed here for
// the tenant zone.
const DNSStubAddr = "127.0.0.54:53"

const dnsProxyTimeout = 5 * time.Second

// DNSProxy is the client end of Geneza's split DNS: a tiny local UDP resolver
// that relays each query, verbatim wire-format, to the gateway's policy-aware
// resolver over the already-authenticated mTLS channel (the Resolve closure),
// and writes the reply back. The system resolver is pointed here for the tenant
// zone only (see SetLinkResolver); everything else stays on the normal upstream.
type DNSProxy struct {
	conn    *net.UDPConn
	resolve func(ctx context.Context, query []byte) ([]byte, error)
}

// StartDNSProxy binds UDP on listenAddr (e.g. "127.0.0.54:53") and serves until
// the returned stop() is called. resolve does the gateway round-trip.
func StartDNSProxy(listenAddr string, resolve func(ctx context.Context, query []byte) ([]byte, error)) (*DNSProxy, error) {
	ua, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, fmt.Errorf("bind dns proxy %s: %w", listenAddr, err)
	}
	p := &DNSProxy{conn: conn, resolve: resolve}
	go p.serve()
	return p, nil
}

func (p *DNSProxy) serve() {
	buf := make([]byte, 4096) // a UDP DNS message is <=4096 with EDNS0
	for {
		n, from, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return // conn closed
		}
		query := make([]byte, n)
		copy(query, buf[:n])
		go func(q []byte, addr *net.UDPAddr) {
			ctx, cancel := context.WithTimeout(context.Background(), dnsProxyTimeout)
			defer cancel()
			resp, err := p.resolve(ctx, q)
			if err != nil || len(resp) == 0 {
				return // drop: the client retries / falls through
			}
			_, _ = p.conn.WriteToUDP(resp, addr)
		}(query, from)
	}
}

// Addr is the proxy's listen address.
func (p *DNSProxy) Addr() string { return p.conn.LocalAddr().String() }

// Close stops serving.
func (p *DNSProxy) Close() error { return p.conn.Close() }
