package netmap

import (
	"context"
	"errors"
	"sync"
	"time"
)

// maxResults bounds the views a result cache keeps (each a few hundred KiB at most).
const maxResults = 32

// resultCache keeps the views built in the last ttl by request, so that the same request -
// the dashboard's refresh, a second tab - is answered without building it again, and requests
// that arrive while it is being built wait for that build instead of starting their own.
type resultCache[T any] struct {
	ttl time.Duration // negative: nothing is kept
	now func() time.Time

	mu sync.Mutex
	m  map[string]*result[T]
}

// result is one view, being built until done is closed.
type result[T any] struct {
	done chan struct{}
	val  T
	err  error
	at   time.Time // when it was built
}

func newResultCache[T any](ttl time.Duration, now func() time.Time) *resultCache[T] {
	return &resultCache[T]{ttl: ttl, now: now, m: map[string]*result[T]{}}
}

// get returns the view kept for key while it is fresh, else builds it with build (once, while
// other callers of the same key wait). A failed build is not kept; a caller whose wait ends
// because the builder's request was cancelled builds the view itself. A build that panics fails
// the callers waiting for it, and is not kept either: the panic goes on up to the caller that
// built (the web layer recovers it), and the next request builds the view again.
func (c *resultCache[T]) get(ctx context.Context, key string, build func() (T, error)) (T, error) {
	if c.ttl < 0 {
		return build()
	}
	for {
		c.mu.Lock()
		r := c.m[key]
		if r != nil {
			select {
			case <-r.done:
				if c.now().Sub(r.at) < c.ttl && r.err == nil {
					c.mu.Unlock()
					return r.val, nil
				}
				r = nil // stale: built again below
			default:
			}
		}
		if r != nil {
			c.mu.Unlock()
			select {
			case <-r.done:
			case <-ctx.Done():
				var zero T
				return zero, ctx.Err()
			}
			if r.err == nil || !isContextErr(r.err) || ctx.Err() != nil {
				return r.val, r.err
			}
			continue // the builder gave up; this caller still wants the view
		}
		r = &result[T]{done: make(chan struct{})}
		c.m[key] = r
		c.mu.Unlock()
		return c.run(key, r, build)
	}
}

// errBuildFailed is what the callers waiting for a build that panicked get.
var errBuildFailed = errors.New("netmap: building the view failed")

// run runs build for the entry r of key and publishes its outcome to the callers waiting for
// it - also when build panics (or ends its goroutine): r is then failed and dropped, so that no
// caller waits for it for ever and the next one builds again. The panic itself is not recovered:
// it goes on, with the stack where it happened, to the caller's recovery.
func (c *resultCache[T]) run(key string, r *result[T], build func() (T, error)) (T, error) {
	finished := false
	defer func() {
		if !finished {
			var zero T
			c.publish(key, r, zero, errBuildFailed)
		}
	}()
	val, err := build()
	finished = true
	c.publish(key, r, val, err)
	return val, err
}

// publish sets the outcome of r, wakes the callers waiting for it and drops it when it failed.
func (c *resultCache[T]) publish(key string, r *result[T], val T, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	r.val, r.err, r.at = val, err, c.now()
	close(r.done)
	if err != nil && c.m[key] == r {
		delete(c.m, key)
	}
	c.trim()
}

// trim drops stale views and, beyond maxResults, the oldest ones (c.mu held). Views still being
// built stay.
func (c *resultCache[T]) trim() {
	now := c.now()
	for {
		var oldestKey string
		var oldest time.Time
		built := 0
		for k, r := range c.m {
			select {
			case <-r.done:
			default:
				continue
			}
			if now.Sub(r.at) >= c.ttl {
				delete(c.m, k)
				continue
			}
			built++
			if oldestKey == "" || r.at.Before(oldest) {
				oldestKey, oldest = k, r.at
			}
		}
		if built <= maxResults {
			return
		}
		delete(c.m, oldestKey)
	}
}

// isContextErr reports whether err says that a request was cancelled or timed out.
func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
