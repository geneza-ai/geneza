package controller

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// realtimeBus is the transport behind the deny-path doorbell: it delivers a peer's
// doorbell ring to this controller and lets this controller ring a peer. Postgres backs
// it with LISTEN/NOTIFY (an instant push); MySQL has no native pub/sub, so its bus
// polls the authoritative deny rows on a sub-TTL timer — correct by construction
// because the deny cache fails closed, so the poll only debounces a re-read the
// short-TTL cache would force anyway.
//
// The router never touches the database for routing/doorbells directly; it goes
// through this seam, so the only engine-specific code in the data path lives here.
type realtimeBus interface {
	// crossControllerNotify rings another controller's own doorbell channel. On Postgres
	// this is a pg_notify; on MySQL there is no push, so it returns errNoCrossPush
	// and the caller falls back to its owed/sweep backstop.
	crossControllerNotify(ctx context.Context, channel, payload string) error
	// Close stops the bus and releases its resources.
	Close()
}

// errNoCrossPush is returned by a bus that cannot push a cross-controller doorbell
// (the MySQL poll bus). The caller already treats a non-delivered ring as "owed",
// so the owner's sweep / the agent's reconnect reconcile re-drives it.
var errNoCrossPush = errors.New("realtime bus has no cross-controller push")

// busHandler is the set of callbacks a bus drives when a doorbell arrives (or, on
// the poll bus, when a watched row changes). The router implements it.
type busHandler interface {
	// onDoorbell is called for a delivered doorbell on one of the deny/config/
	// own-controller channels, with the raw channel name and payload.
	onDoorbell(channel, payload string)
	// onResync is called whenever the bus (re)establishes delivery and may have
	// missed events: the handler flushes its caches and re-reads authoritative state.
	onResync()
	// flushDeny drops the deny cache without re-reading the config — the poll bus
	// calls it every tick so a peer's suspend/revoke/lift becomes visible within a
	// cache lifetime even though there is no push channel.
	flushDeny()
	// onConfigChanged re-reads and adopts the stored cluster config (a follower
	// apply), called when the poll bus observes the config version advance.
	onConfigChanged()
	// denyChannels are the channels the bus subscribes to (the four deny-path
	// channels plus this controller's own doorbell). The poll bus ignores them.
	denyChannels() []string
}

// --- Postgres LISTEN/NOTIFY bus ---

// pgBus owns a dedicated pgxpool used ONLY for pg_notify and the hijacked LISTEN
// connection — the one place pgx survives the move to database/sql, because
// LISTEN/NOTIFY is a Postgres-wire feature database/sql does not expose. A blip on
// this pool must degrade to "the deny cache fails closed on the next read", never
// crash the controller, so the LISTEN loop reconnects with backoff.
type pgBus struct {
	pool    *pgxpool.Pool
	handler busHandler
	cancel  context.CancelFunc
	done    chan struct{}
}

func newPGBus(ctx context.Context, dsn string, handler busHandler) (*pgBus, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	bctx, cancel := context.WithCancel(context.Background())
	b := &pgBus{pool: pool, handler: handler, cancel: cancel, done: make(chan struct{})}
	go b.listen(bctx)
	return b, nil
}

func (b *pgBus) crossControllerNotify(ctx context.Context, channel, payload string) error {
	_, err := b.pool.Exec(ctx, "SELECT pg_notify($1, $2)", channel, payload)
	return err
}

func (b *pgBus) Close() {
	b.cancel()
	<-b.done
	b.pool.Close()
}

// listen runs the dedicated LISTEN loop, reconnecting + resyncing on any fault.
func (b *pgBus) listen(ctx context.Context) {
	defer close(b.done)
	var conn *pgx.Conn
	for {
		if conn == nil {
			c, err := b.connectAndResync(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Second):
				}
				continue
			}
			conn = c
		}
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			_ = conn.Close(context.Background())
			conn = nil // force a reconnect + resync
			if ctx.Err() != nil {
				return
			}
			continue
		}
		b.handler.onDoorbell(n.Channel, n.Payload)
	}
}

// connectAndResync acquires a hijacked LISTEN connection and issues the LISTENs.
// Because a reconnect may have missed doorbells, it resyncs (flush + re-read)
// BEFORE trusting any new delta.
func (b *pgBus) connectAndResync(ctx context.Context) (*pgx.Conn, error) {
	acq, err := b.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	conn := acq.Hijack()
	for _, ch := range b.handler.denyChannels() {
		if _, err := conn.Exec(ctx, "LISTEN "+pgx.Identifier{ch}.Sanitize()); err != nil {
			_ = conn.Close(context.Background())
			return nil, err
		}
	}
	b.handler.onResync()
	return conn, nil
}

// --- MySQL poll bus ---

// pollBusInterval is how often the poll bus re-reads the config version and flushes
// the deny cache. It must be at most the deny-cache TTL so a missed change is
// visible within one cache lifetime; the cache itself fails closed on any read
// error, so the poll is purely an optimization that turns a forced re-read into a
// proactive one.
const pollBusInterval = time.Second

// pollBus is the MySQL realtime bus: it has no push channel, so on a fixed timer it
// flushes the deny cache (so a suspension/revoke written by any controller is re-read
// within a tick) and re-reads the cluster-config version (firing the config-adopt
// callback when it advances). Cross-controller doorbells are not delivered; the caller
// treats a non-push as "owed" and the sweep/reconnect backstops re-drive it.
type pollBus struct {
	store   *sqlStore
	handler busHandler
	cancel  context.CancelFunc
	done    chan struct{}
}

func newPollBus(store *sqlStore, handler busHandler) *pollBus {
	ctx, cancel := context.WithCancel(context.Background())
	b := &pollBus{store: store, handler: handler, cancel: cancel, done: make(chan struct{})}
	go b.run(ctx)
	return b
}

func (b *pollBus) crossControllerNotify(context.Context, string, string) error {
	return errNoCrossPush
}

func (b *pollBus) Close() {
	b.cancel()
	<-b.done
}

func (b *pollBus) run(ctx context.Context) {
	defer close(b.done)
	// An initial resync mirrors the LISTEN bus adopting the stored config on connect.
	b.handler.onResync()
	var lastVersion int64 = -1
	if v, err := b.store.ClusterConfigVersion(); err == nil {
		lastVersion = v
	}
	ticker := time.NewTicker(pollBusInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Flush the deny cache every tick so a peer's suspend/revoke/lift is
			// re-read within a cache lifetime even without a push channel.
			b.handler.flushDeny()
			v, err := b.store.ClusterConfigVersion()
			if err != nil {
				slog.Debug("poll bus: cluster config version read failed", "err", err)
				continue
			}
			if v != lastVersion {
				lastVersion = v
				b.handler.onConfigChanged()
			}
		}
	}
}
