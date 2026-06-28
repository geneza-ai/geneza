package sessionconn

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/pion/ice/v4"

	"geneza.io/internal/icewire"
)

// Path classes reported back for a connected session (the `path` attribute).
const (
	PathDirect  = "direct"
	PathRelayed = "relayed"
)

const defaultGatherTimeout = 8 * time.Second

// maxRemoteCandidates caps how many remote candidates one session will ingest,
// so a peer (or a compromised forwarder) cannot trickle an unbounded stream that
// turns this agent into a STUN-probe amplifier toward attacker-named addresses
// . Past the cap, candidates are dropped (not errored) so legitimate
// re-trickle within the cap still works.
const maxRemoteCandidates = 40

// Signal is one inbound ICE signaling message from the remote peer: exactly one
// of (Ufrag/Pwd) — the remote's ICE credentials — or Candidate — one trickled
// remote candidate (a pion ice.Candidate.Marshal() string).
type Signal struct {
	Ufrag     string
	Pwd       string
	Candidate string
}

// Signaler exchanges ICE creds + candidates with the remote peer THROUGH the
// controller — the client over the SessionSignal stream, the agent over its
// NodeControl disco path. The controller forwards only between the two principals
// named in the brokered grant; it never sees session data.
type Signaler interface {
	SendCreds(ufrag, pwd string) error
	SendCandidate(cand string) error
	// Recv blocks for the next remote signal, or returns ctx.Err().
	Recv(ctx context.Context) (*Signal, error)
}

// Config is one session's ICE setup, minted by the controller broker.
type Config struct {
	Controlling bool   // controller-assigned ICE role: the controlling side Dials, the other Accepts
	TurnURL     string // "turn:host:7404?transport=udp" — the relay floor; "" = host-only (tests)
	TurnUser    string
	TurnPass    string
	// Candidates is the region-tagged relay set from the signed grant. When set it
	// supersedes the scalar TurnURL trio; pion is handed every relay and picks the
	// lowest-latency working one, re-nominating past a blackhole. Empty falls back
	// to the single scalar relay, identical to before.
	Candidates []icewire.RelayCred
	RelayOnly  bool          // force the TURN floor (require_relay)
	Gather     time.Duration // bound the gather/connect; 0 = default
}

// sessionConn wraps the selected *ice.Conn so closing it also closes the ICE
// agent and stops the candidate-receive loop.
type sessionConn struct {
	net.Conn
	agent  *ice.Agent
	cancel context.CancelFunc
}

func (c *sessionConn) Close() error {
	c.cancel()
	err := c.Conn.Close()
	_ = c.agent.Close()
	return err
}

// Connect runs ICE for ONE session and returns a connected net.Conn (the
// selected *ice.Conn — direct UDP when hole-punchable, TURN-relayed under hard
// NAT) plus the path class. It is the AVAILABILITY layer only: the caller wraps
// the returned conn in the UNCHANGED E2E Noise tunnel, which stays the security
// boundary. ICE never decides who may connect — the Noise+grant gate does.
func Connect(ctx context.Context, cfg Config, sig Signaler) (net.Conn, string, error) {
	creds := cfg.Candidates
	if len(creds) == 0 && cfg.TurnURL != "" {
		creds = []icewire.RelayCred{{TurnURL: cfg.TurnURL, TurnUser: cfg.TurnUser, TurnPass: cfg.TurnPass}}
	}
	urls, candTypes, err := icewire.URLsMulti(creds, cfg.RelayOnly)
	if err != nil {
		return nil, "", err
	}
	// Sessions are interactive and revocable, so we want PROMPT peer-death
	// detection (a crashed client, a killed worker, a cut path) — far faster than
	// the pion defaults. Over UDP there is no instant FIN, so detection is by
	// consent-freshness: ~keepalive*N. These bound a dead session to a few seconds,
	// after which the OnConnectionStateChange watchdog tears it down.
	disconnected := 3 * time.Second
	failed := 5 * time.Second
	keepalive := 1 * time.Second
	a, err := ice.NewAgent(&ice.AgentConfig{
		Urls:                urls,
		NetworkTypes:        []ice.NetworkType{ice.NetworkTypeUDP4},
		CandidateTypes:      candTypes,
		DisconnectedTimeout: &disconnected,
		FailedTimeout:       &failed,
		KeepaliveInterval:   &keepalive,
		// Reject remote candidates that name targets that are never a valid ICE
		// peer (unspecified / multicast / link-local), shrinking the reflection
		// surface; the count cap below bounds the rest. (Returns true = allow.)
		RemoteIPFilter: func(ip net.IP) bool {
			return !(ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast())
		},
	})
	if err != nil {
		return nil, "", fmt.Errorf("ice agent: %w", err)
	}

	// Path class is derived from the selected pair: a relay candidate on either
	// end means the session is relayed; otherwise it's direct.
	var pathRelayed atomic.Bool
	pathRelayed.Store(true) // conservative default until a pair is selected
	_ = a.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		pathRelayed.Store(icewire.IsRelayed(local, remote))
	})

	// Trickle our local candidates to the peer as they're gathered.
	_ = a.OnCandidate(func(c ice.Candidate) {
		if c == nil { // gathering complete
			return
		}
		_ = sig.SendCandidate(c.Marshal())
	})
	if err := a.GatherCandidates(); err != nil {
		_ = a.Close()
		return nil, "", fmt.Errorf("gather: %w", err)
	}
	ufrag, pwd, err := a.GetLocalUserCredentials()
	if err != nil {
		_ = a.Close()
		return nil, "", fmt.Errorf("local creds: %w", err)
	}
	if err := sig.SendCreds(ufrag, pwd); err != nil {
		_ = a.Close()
		return nil, "", fmt.Errorf("send creds: %w", err)
	}

	gather := cfg.Gather
	if gather <= 0 {
		gather = defaultGatherTimeout
	}
	// Split AVAILABILITY from SESSION LIFETIME: the recv goroutine + the returned
	// conn live on sessCtx (cancelled only on Close / ICE-failure) so candidate
	// trickle keeps flowing for re-nomination the WHOLE session; only the
	// creds-wait + Dial/Accept is bounded by the gather timeout. (Previously the
	// conn rode the gather-timeout ctx and self-destructed ~gather s after connect.)
	sessCtx, sessCancel := context.WithCancel(ctx)

	// ICE-failure watchdog: pion does not unblock a parked Read on Failed (and a
	// post-Failed Write silently succeeds), so a wedged path would hang the
	// SCTP/Noise/SSH stack forever. On Failed, cancel the session + close the agent
	// (async, to avoid re-entrancy in the pion callback) to unblock readers.
	_ = a.OnConnectionStateChange(func(st ice.ConnectionState) {
		if st == ice.ConnectionStateFailed {
			sessCancel()
			go func() { _ = a.Close() }()
		}
	})

	// Receive remote creds + candidates for the LIFE of the session (re-nomination).
	var remoteUfrag, remotePwd atomic.Value
	credCh := make(chan struct{})
	go func() {
		var gotCreds bool
		var candCount int
		for {
			s, err := sig.Recv(sessCtx)
			if err != nil {
				return
			}
			if s.Ufrag != "" {
				remoteUfrag.Store(s.Ufrag)
				remotePwd.Store(s.Pwd)
				if !gotCreds {
					gotCreds = true
					close(credCh)
				}
			} else if s.Candidate != "" {
				if candCount >= maxRemoteCandidates {
					continue // cap remote candidates per session (a peer must not flood us)
				}
				if c, e := ice.UnmarshalCandidate(s.Candidate); e == nil {
					if a.AddRemoteCandidate(c) == nil {
						candCount++
					}
				}
			}
		}
	}()

	dialCtx, dialCancel := context.WithTimeout(sessCtx, gather)
	defer dialCancel()
	select {
	case <-credCh:
	case <-dialCtx.Done():
		sessCancel()
		_ = a.Close()
		return nil, "", fmt.Errorf("timed out waiting for peer ICE credentials")
	}
	ru, _ := remoteUfrag.Load().(string)
	rp, _ := remotePwd.Load().(string)

	var conn *ice.Conn
	if cfg.Controlling {
		conn, err = a.Dial(dialCtx, ru, rp)
	} else {
		conn, err = a.Accept(dialCtx, ru, rp)
	}
	if err != nil {
		sessCancel()
		_ = a.Close()
		return nil, "", fmt.Errorf("ice connect: %w", err)
	}
	return &sessionConn{Conn: conn, agent: a, cancel: sessCancel}, classifyPath(a, &pathRelayed), nil
}

// classifyPath returns the path class of the connected session. It reads the
// selected pair authoritatively (it is nominated by the time Dial/Accept
// returns); the atomic set by OnSelectedCandidatePairChange is the fallback if
// the query races, and the conservative default is "relayed".
func classifyPath(a *ice.Agent, pathRelayed *atomic.Bool) string {
	if pair, err := a.GetSelectedCandidatePair(); err == nil && pair != nil && pair.Local != nil && pair.Remote != nil {
		if icewire.IsRelayed(pair.Local, pair.Remote) {
			return PathRelayed
		}
		return PathDirect
	}
	if pathRelayed.Load() {
		return PathRelayed
	}
	return PathDirect
}
