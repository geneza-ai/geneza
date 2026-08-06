package controller

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"sync"

	genezav1 "geneza.io/internal/pb/geneza/v1"
)

// The node control stream's receive loop must never do slow work.
//
// Ingesting an inventory report re-indexes the node's components and then matches
// every one of them against the advisory store. That is O(components × advisories)
// and, on a large SBOM against a full OSV feed, runs for minutes. It used to run
// INLINE in `for { stream.Recv() }`, so while it ground away the controller stopped
// reading that agent's stream at all. Backpressure then wedged the agent itself:
// its control-stream sends have no deadline, one blocked SendMsg holds the send
// mutex, and offer acks queue behind it — which surfaces as "did not ack session
// offer within 5s" and a stale LAST-SEEN on a process that looks perfectly alive.
//
// So the ingest stays synchronous (its error still decides whether to ask the node
// for a full re-send, and every test keeps its straight-line semantics); it is the
// DISPATCH that moves off the loop, onto a small bounded pool.

// inventoryQueue is a bounded worker pool for inventory ingestion.
type inventoryQueue struct {
	jobs   chan inventoryJob
	wg     sync.WaitGroup
	closed chan struct{}
	once   sync.Once
}

type inventoryJob struct {
	ctx    context.Context
	ws     string
	nodeID string
	report *genezav1.InventoryReport
}

// inventoryQueueDepth bounds how many reports may wait. A dropped report is not a
// lost one: the agent re-reports on its own interval, and an unchanged SBOM hash
// makes the redo a no-op. Blocking here would recreate the exact stall this file
// exists to prevent.
const inventoryQueueDepth = 64

func newInventoryQueue(workers int, run func(inventoryJob)) *inventoryQueue {
	if workers <= 0 {
		workers = max(1, min(4, runtime.NumCPU()/2))
	}
	q := &inventoryQueue{
		jobs:   make(chan inventoryJob, inventoryQueueDepth),
		closed: make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		q.wg.Add(1)
		go func() {
			defer q.wg.Done()
			for job := range q.jobs {
				run(job)
			}
		}()
	}
	return q
}

// submit queues a job, reporting false if the queue is full or shutting down.
func (q *inventoryQueue) submit(job inventoryJob) bool {
	select {
	case <-q.closed:
		return false
	default:
	}
	select {
	case q.jobs <- job:
		return true
	default:
		return false
	}
}

func (q *inventoryQueue) stop() {
	q.once.Do(func() {
		close(q.closed)
		close(q.jobs)
		q.wg.Wait()
	})
}

// startInventoryQueue wires the server's queue. Idempotent.
func (s *Server) startInventoryQueue() {
	if s.invQueue != nil {
		return
	}
	s.invQueue = newInventoryQueue(0, func(job inventoryJob) {
		if _, err := s.ingestInventoryReport(job.ctx, job.ws, job.nodeID, job.report); err != nil {
			// A delta whose base we no longer hold: ask the node for a full SBOM so
			// both ends re-converge. Other errors are corruption/policy rejections.
			if errors.Is(err, errInventoryNeedFull) {
				if cerr := s.registry.SendInventoryControl(job.nodeID, true); cerr != nil {
					slog.Debug("inventory full-resend request not delivered", "node", job.nodeID, "err", cerr)
				}
			} else {
				slog.Warn("inventory report rejected", "node", job.nodeID, "err", err)
			}
		}
	})
}

// queueInventoryReport hands a report to the pool. It returns immediately so the
// caller's control stream keeps draining.
func (s *Server) queueInventoryReport(ctx context.Context, ws, nodeID string, report *genezav1.InventoryReport) {
	if s.invQueue == nil {
		s.startInventoryQueue()
	}
	if !s.invQueue.submit(inventoryJob{ctx: ctx, ws: ws, nodeID: nodeID, report: report}) {
		slog.Warn("inventory queue full; dropping this report (the node re-reports on its own interval)",
			"component", "inventory", "node", nodeID)
	}
}
