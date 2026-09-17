package relay

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/xyluxx/burndrop/internal/crypto"
)

// redisPrefix namespaces every key the relay writes.
const redisPrefix = "burndrop:"

// redisPollInterval is how often Wait re-reads a slot. Redis has no cheap
// per-key change signal that survives reconnects, so long polls poll.
const redisPollInterval = 200 * time.Millisecond

// redisTimeout bounds calls that have no request context.
const redisTimeout = 5 * time.Second

// Redis is the optional store for deployments with more than one relay
// replica. Each slot is one hash, and every method that reads or changes a
// slot runs as a single Lua script, so token verification, state checks, and
// the read-and-delete of ciphertext are atomic on the server. The clock is
// always passed in from the store, never read from Redis.
//
// Keys under the prefix: slot:<id> is a hash of kind, state, ct, commitment,
// ta, tb, agent and the timestamps created, expires, uploaded, fetched,
// revoked in unix milliseconds; expiry is a sorted set of live ids scored by
// expiry time; removal is a sorted set of all ids scored by expiry plus
// grace; live and bytes are counters. Every slot key also carries a PEXPIRE
// at expiry plus grace so tombstones vanish even when no sweeper runs.
type Redis struct {
	opts   StoreOptions
	client *redis.Client
	prefix string
}

// newRedisStore builds the Redis store from the relay configuration.
func newRedisStore(cfg Config, now func() time.Time) (Store, error) {
	s, err := NewRedis(cfg.RedisURL, StoreOptions{MaxLive: cfg.MaxLiveDrops, MaxBytes: cfg.MaxTotalBytes, Now: now})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// NewRedis connects to a redis:// or rediss:// URL and checks that the server
// answers before returning.
func NewRedis(url string, opts StoreOptions) (*Redis, error) {
	return newRedis(url, redisPrefix, opts)
}

// redisNoLog silences the client library's own logger, which writes raw lines
// to stderr. Everything the relay reports goes through its logger, where the
// format, the level, and the rule against identifiers in logs are enforced;
// connection failures still reach callers as errors.
type redisNoLog struct{}

func (redisNoLog) Printf(context.Context, string, ...any) {}

func newRedis(url, prefix string, opts StoreOptions) (*Redis, error) {
	ro, err := redis.ParseURL(url)
	if err != nil {
		// The parser's message can echo the URL, credentials included.
		return nil, errors.New("relay: invalid redis URL, want redis://host:port/db or rediss://host:port/db")
	}
	redis.SetLogger(redisNoLog{})
	client := redis.NewClient(ro)
	ctx, cancel := context.WithTimeout(context.Background(), redisTimeout)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("relay: redis at %s is unreachable: %w", ro.Addr, err)
	}
	return &Redis{opts: opts.withDefaults(), client: client, prefix: prefix}, nil
}

// Every script gets KEYS slot, expiry, removal, live, bytes and ARGV now
// (unix milliseconds from the store clock), id, then its own arguments. The
// prelude mirrors the memory store's helpers: get applies lazy expiry,
// release takes a live slot out of the counters, tombstone clears everything
// but state and timestamps. Replies are {code, kind, state, created, expires,
// uploaded, fetched, revoked, payload} or just {code}.
const redisPrelude = `
local slot, expiry, removal, live, bytes = KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5]
local now = tonumber(ARGV[1])
local id = ARGV[2]

local function terminal(state)
  return state == 'fetched' or state == 'opened' or state == 'revoked' or state == 'expired'
end

local function counter(key)
  return tonumber(redis.call('GET', key)) or 0
end

local function release()
  local n = redis.call('HSTRLEN', slot, 'ct')
  if n > 0 then redis.call('INCRBY', bytes, -n) end
  redis.call('DECR', live)
  redis.call('ZREM', expiry, id)
end

local function tombstone(d, state, at)
  redis.call('HDEL', slot, 'ct', 'commitment', 'ta', 'tb')
  d.state, d.commitment, d.ta, d.tb = state, '', '', ''
  if state == 'fetched' or state == 'opened' then
    d.fetched = tonumber(at)
    redis.call('HSET', slot, 'state', state, 'fetched', at)
  elseif state == 'revoked' then
    d.revoked = tonumber(at)
    redis.call('HSET', slot, 'state', state, 'revoked', at)
  else
    redis.call('HSET', slot, 'state', state)
  end
end

local function get()
  local f = redis.call('HMGET', slot, 'kind', 'state', 'created', 'expires', 'uploaded', 'fetched', 'revoked', 'commitment', 'ta', 'tb')
  if not f[2] then return nil end
  local d = {
    kind = f[1] or '', state = f[2],
    created = tonumber(f[3]) or 0, expires = tonumber(f[4]) or 0, uploaded = tonumber(f[5]) or 0,
    fetched = tonumber(f[6]) or 0, revoked = tonumber(f[7]) or 0,
    commitment = f[8] or '', ta = f[9] or '', tb = f[10] or '',
  }
  if not terminal(d.state) and now >= d.expires then
    release()
    tombstone(d, 'expired', '0')
  end
  return d
end

local function reply(code, d, payload)
  return {code, d.kind, d.state, d.created, d.expires, d.uploaded, d.fetched, d.revoked, payload or ''}
end
`

var (
	// ARGV: kind, state, commitment, ta, tb, agent, created, expires,
	// uploaded, fetched, revoked, ct, maxLive, maxBytes, removeAt.
	redisCreate = redis.NewScript(redisPrelude + `
if redis.call('EXISTS', slot) == 1 then return {'full'} end
local n = #ARGV[14]
local maxLive, maxBytes = tonumber(ARGV[15]), tonumber(ARGV[16])
if maxLive > 0 and counter(live) >= maxLive then return {'full'} end
if maxBytes > 0 and counter(bytes) + n > maxBytes then return {'full'} end
redis.call('HSET', slot, 'kind', ARGV[3], 'state', ARGV[4], 'commitment', ARGV[5], 'ta', ARGV[6], 'tb', ARGV[7], 'agent', ARGV[8],
  'created', ARGV[9], 'expires', ARGV[10], 'uploaded', ARGV[11], 'fetched', ARGV[12], 'revoked', ARGV[13])
if n > 0 then
  redis.call('HSET', slot, 'ct', ARGV[14])
  redis.call('INCRBY', bytes, n)
end
redis.call('INCR', live)
redis.call('ZADD', expiry, ARGV[10], id)
redis.call('ZADD', removal, ARGV[17], id)
local ttl = tonumber(ARGV[17]) - now
if ttl < 1 then ttl = 1 end
redis.call('PEXPIRE', slot, ttl)
return {'ok'}
`)

	// ARGV: token, commitment, ct, maxBytes.
	redisUpload = redis.NewScript(redisPrelude + `
local d = get()
if not d then return {'notfound'} end
if d.kind ~= 'drop' then return {'wrongkind'} end
if terminal(d.state) then return reply('state', d) end
if d.ta ~= ARGV[3] then return {'badtoken'} end
if d.state ~= 'created' then return reply('state', d) end
if d.commitment ~= ARGV[4] then return {'commitment'} end
local n = #ARGV[5]
local maxBytes = tonumber(ARGV[6])
if maxBytes > 0 and counter(bytes) + n > maxBytes then return {'full'} end
redis.call('HSET', slot, 'ct', ARGV[5], 'state', 'uploaded', 'uploaded', ARGV[1])
if n > 0 then redis.call('INCRBY', bytes, n) end
return {'ok'}
`)

	// ARGV: token.
	redisFetch = redis.NewScript(redisPrelude + `
local d = get()
if not d then return {'notfound'} end
if d.kind ~= 'drop' then return {'wrongkind'} end
if terminal(d.state) then return reply('state', d) end
if d.tb ~= ARGV[3] then return {'badtoken'} end
if d.state ~= 'uploaded' then return reply('state', d) end
local ct = redis.call('HGET', slot, 'ct') or ''
release()
tombstone(d, 'fetched', ARGV[1])
return reply('ok', d, ct)
`)

	// ARGV: token.
	redisOpen = redis.NewScript(redisPrelude + `
local d = get()
if not d then return {'notfound'} end
if d.kind ~= 'reveal' then return {'wrongkind'} end
if terminal(d.state) then return reply('state', d) end
if d.ta ~= ARGV[3] then return {'badtoken'} end
local ct = redis.call('HGET', slot, 'ct') or ''
release()
tombstone(d, 'opened', ARGV[1])
return reply('ok', d, ct)
`)

	// ARGV: token.
	redisRevoke = redis.NewScript(redisPrelude + `
local d = get()
if not d then return {'notfound'} end
if terminal(d.state) then return reply('state', d) end
if d.ta ~= ARGV[3] and d.tb ~= ARGV[3] then return {'badtoken'} end
release()
tombstone(d, 'revoked', ARGV[1])
return {'ok'}
`)

	redisStatus = redis.NewScript(redisPrelude + `
local d = get()
if not d then return {'notfound'} end
return reply('ok', d)
`)

	// redisExpire moves one due live slot to expired; it returns 1 when it did.
	redisExpire = redis.NewScript(redisPrelude + `
local f = redis.call('HMGET', slot, 'state', 'expires')
if not f[1] or terminal(f[1]) then
  redis.call('ZREM', expiry, id)
  return 0
end
if now < (tonumber(f[2]) or 0) then return 0 end
release()
tombstone({}, 'expired', '0')
return 1
`)

	// redisRemove deletes one slot whose grace period is over; it returns 1
	// when a key was removed.
	redisRemove = redis.NewScript(redisPrelude + `
redis.call('ZREM', removal, id)
local state = redis.call('HGET', slot, 'state')
if not state then
  redis.call('ZREM', expiry, id)
  return 0
end
if not terminal(state) then release() end
redis.call('DEL', slot)
redis.call('ZREM', expiry, id)
return 1
`)
)

// redisReply is a decoded script result.
type redisReply struct {
	code    string
	drop    Drop
	payload []byte
}

func (r *Redis) keys(id string) []string {
	return []string{r.prefix + "slot:" + id, r.prefix + "expiry", r.prefix + "removal", r.prefix + "live", r.prefix + "bytes"}
}

// run executes one of the fixed scripts above on one slot, with the clock
// and id prepended to args.
func (r *Redis) run(ctx context.Context, script *redis.Script, id string, args ...any) (any, error) {
	all := append([]any{r.opts.Now().UnixMilli(), id}, args...)
	v, err := script.Run(ctx, r.client, r.keys(id), all...).Result()
	if err != nil {
		return nil, fmt.Errorf("relay: redis: %w", err)
	}
	return v, nil
}

// slot runs a script and maps its reply code to the store errors.
func (r *Redis) slot(ctx context.Context, script *redis.Script, id string, args ...any) (redisReply, error) {
	v, err := r.run(ctx, script, id, args...)
	if err != nil {
		return redisReply{}, err
	}
	arr, ok := v.([]any)
	if !ok || len(arr) == 0 {
		return redisReply{}, errors.New("relay: redis: unexpected script reply")
	}
	rep := redisReply{code: redisString(arr[0])}
	if len(arr) >= 9 {
		rep.drop = Drop{
			ID: id, Kind: Kind(redisString(arr[1])), State: State(redisString(arr[2])),
			CreatedAt: redisTime(arr[3]), ExpiresAt: redisTime(arr[4]), UploadedAt: redisTime(arr[5]),
			FetchedAt: redisTime(arr[6]), RevokedAt: redisTime(arr[7]),
		}
		if s := redisString(arr[8]); s != "" {
			rep.payload = []byte(s)
		}
	}
	switch rep.code {
	case "ok":
		return rep, nil
	case "notfound":
		return rep, ErrNotFound
	case "badtoken":
		return rep, ErrBadToken
	case "commitment":
		return rep, ErrCommitment
	case "full":
		return rep, ErrFull
	case "wrongkind":
		return rep, ErrWrongKind
	case "state":
		return rep, rep.drop.stateError()
	}
	return rep, errors.New("relay: redis: unexpected script reply")
}

func redisString(v any) string {
	s, _ := v.(string)
	return s
}

// redisTime converts a millisecond reply; 0 means unset.
func redisTime(v any) time.Time {
	n, _ := v.(int64)
	if n == 0 {
		return time.Time{}
	}
	return time.UnixMilli(n).UTC()
}

// redisMillis is the inverse of redisTime.
func redisMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func (r *Redis) Create(ctx context.Context, d *Drop) error {
	state := d.State
	if state == "" {
		state = StateCreated
	}
	removeAt := d.ExpiresAt.Add(r.opts.TombstoneGrace)
	_, err := r.slot(ctx, redisCreate, d.ID,
		string(d.Kind), string(state), d.Commitment, d.TokenA.Encode(), d.TokenB.Encode(), d.AgentKeyID,
		redisMillis(d.CreatedAt), redisMillis(d.ExpiresAt), redisMillis(d.UploadedAt), redisMillis(d.FetchedAt), redisMillis(d.RevokedAt),
		d.Ciphertext, r.opts.MaxLive, r.opts.MaxBytes, redisMillis(removeAt))
	return err
}

func (r *Redis) Upload(ctx context.Context, id string, token crypto.Hash, commitment string, ciphertext []byte) error {
	_, err := r.slot(ctx, redisUpload, id, token.Encode(), commitment, ciphertext, r.opts.MaxBytes)
	return err
}

func (r *Redis) Fetch(ctx context.Context, id string, token crypto.Hash) ([]byte, time.Time, error) {
	rep, err := r.slot(ctx, redisFetch, id, token.Encode())
	if err != nil {
		return nil, time.Time{}, err
	}
	return rep.payload, rep.drop.UploadedAt, nil
}

func (r *Redis) Open(ctx context.Context, id string, token crypto.Hash) ([]byte, time.Time, error) {
	rep, err := r.slot(ctx, redisOpen, id, token.Encode())
	if err != nil {
		return nil, time.Time{}, err
	}
	return rep.payload, rep.drop.CreatedAt, nil
}

func (r *Redis) Revoke(ctx context.Context, id string, token crypto.Hash) error {
	_, err := r.slot(ctx, redisRevoke, id, token.Encode())
	return err
}

func (r *Redis) Status(ctx context.Context, id string) (Status, error) {
	rep, err := r.slot(ctx, redisStatus, id)
	if err != nil {
		return Status{}, err
	}
	return rep.drop.status(), nil
}

func (r *Redis) Wait(ctx context.Context, id string, current State, timeout time.Duration) (Status, error) {
	st, err := r.Status(ctx, id)
	if err != nil || st.State != current || timeout <= 0 {
		return st, err
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(redisPollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return r.lastStatus(ctx, id)
		case <-deadline.C:
			return r.Status(ctx, id)
		case <-tick.C:
		}
		st, err = r.Status(ctx, id)
		if err != nil {
			if ctx.Err() != nil {
				return r.lastStatus(ctx, id)
			}
			return st, err
		}
		if st.State != current {
			return st, nil
		}
	}
}

// lastStatus reads a slot once more after the caller's context ended, so a
// cancelled long poll still reports the current state like the memory store.
func (r *Redis) lastStatus(ctx context.Context, id string) (Status, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), redisTimeout)
	defer cancel()
	return r.Status(ctx, id)
}

func (r *Redis) Sweep() int {
	ctx, cancel := context.WithTimeout(context.Background(), redisTimeout)
	defer cancel()
	now := strconv.FormatInt(r.opts.Now().UnixMilli(), 10)
	return r.sweepSet(ctx, r.prefix+"expiry", now, redisExpire) + r.sweepSet(ctx, r.prefix+"removal", now, redisRemove)
}

// sweepSet runs script on every member of set scored at or before now. Each
// script removes its member, so the loop advances; the first-member check
// stops it if that ever fails.
func (r *Redis) sweepSet(ctx context.Context, set, now string, script *redis.Script) int {
	const batch = 256
	touched := 0
	last := ""
	for {
		ids, err := r.client.ZRangeByScore(ctx, set, &redis.ZRangeBy{Min: "-inf", Max: now, Count: batch}).Result()
		if err != nil || len(ids) == 0 || ids[0] == last {
			return touched
		}
		for _, id := range ids {
			v, err := r.run(ctx, script, id)
			if err != nil {
				return touched
			}
			if n, _ := v.(int64); n == 1 {
				touched++
			}
		}
		if len(ids) < batch {
			return touched
		}
		last = ids[0]
	}
}

func (r *Redis) Stats() Stats {
	ctx, cancel := context.WithTimeout(context.Background(), redisTimeout)
	defer cancel()
	vals, err := r.client.MGet(ctx, r.prefix+"live", r.prefix+"bytes").Result()
	if err != nil || len(vals) != 2 {
		return Stats{}
	}
	total, err := r.client.ZCard(ctx, r.prefix+"removal").Result()
	if err != nil {
		return Stats{}
	}
	live, _ := strconv.ParseInt(redisString(vals[0]), 10, 64)
	bytes, _ := strconv.ParseInt(redisString(vals[1]), 10, 64)
	return Stats{Live: int(live), Bytes: bytes, Total: int(total)}
}

func (r *Redis) Close() error {
	return r.client.Close()
}
