package relay

import (
	"errors"
	"time"
)

// ErrRedisUnavailable is returned until the Redis store lands. The memory
// store is the default and is complete; the Redis store is for multi-replica
// deployments and is implemented in redis_store.go when built with the
// "redis" build tag.
var ErrRedisUnavailable = errors.New("relay: redis store is not compiled into this binary")

// newRedisStore is replaced by the real constructor when the redis build tag
// is present.
var newRedisStore = func(cfg Config, now func() time.Time) (Store, error) {
	return nil, ErrRedisUnavailable
}
