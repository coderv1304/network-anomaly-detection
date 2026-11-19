package state

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisWindowScript appends one flow's points to the host window, prunes entries
// older than the sliding window, refreshes the key TTL, and returns the entry
// count plus the summed risk points. The ZSET score is the event time so range
// pruning is correct; the points travel in the member as "<flowID>:<points>".
const redisWindowScript = `
local key = KEYS[1]
local member = ARGV[1]
local now = tonumber(ARGV[2])
local window = tonumber(ARGV[3])
local expire = tonumber(ARGV[4])
redis.call('ZADD', key, now, member)
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
redis.call('EXPIRE', key, expire)
local entries = redis.call('ZRANGE', key, 0, -1)
local total = 0
for i = 1, #entries do
  local points = tonumber(string.match(entries[i], ':([^:]+)$'))
  if points then
    total = total + points
  end
end
return {#entries, total}
`

// RedisWindowStore keeps each host's sliding window in one sorted set, so the
// score update, expiry, and window sum are a single atomic round trip.
type RedisWindowStore struct {
	client   *redis.Client
	windowS  float64
	fallback *MemoryWindowStore
	logger   *slog.Logger
	healthy  atomic.Bool
}

func newRedisWindowStore(ctx context.Context, redisURL string, window time.Duration, fallback *MemoryWindowStore, logger *slog.Logger) (*RedisWindowStore, error) {
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}
	if options.DialTimeout == 0 {
		options.DialTimeout = 2 * time.Second
	}
	options.ReadTimeout = 2 * time.Second
	options.WriteTimeout = 2 * time.Second
	client := redis.NewClient(options)
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	acc := &RedisWindowStore{
		client:   client,
		windowS:  window.Seconds(),
		fallback: fallback,
		logger:   logger,
	}
	acc.healthy.Store(true)
	return acc, nil
}

func (a *RedisWindowStore) Backend() string {
	if a.healthy.Load() {
		return "redis"
	}
	return "memory"
}

func (a *RedisWindowStore) Close() error {
	return a.client.Close()
}

func (a *RedisWindowStore) Record(ctx context.Context, event Event) (WindowSnapshot, error) {
	if event.SourceIP == "" {
		return WindowSnapshot{}, nil
	}
	nowSeconds := float64(event.TimestampUS) / 1e6
	identity := event.FlowID
	if identity == "" {
		identity = fmt.Sprintf("%d|%s", event.TimestampUS, event.Label)
	}
	member := identity + ":" + strconv.FormatFloat(clampRisk(event.Risk), 'f', -1, 64)
	callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	result, err := a.client.Eval(
		callCtx,
		redisWindowScript,
		[]string{"netshield:win:" + event.SourceIP},
		member,
		nowSeconds,
		a.windowS,
		360,
	).Result()
	if err != nil {
		if a.healthy.Swap(false) && a.logger != nil {
			a.logger.Warn("redis window write failed; falling back to memory", "error", err)
		}
		return a.fallback.Record(context.Background(), event)
	}
	a.healthy.Store(true)
	count, sum := parseWindowResult(result)
	windowUS := int64(a.windowS * 1e6)
	return WindowSnapshot{
		SourceIP:      event.SourceIP,
		Count:         count,
		RiskSum:       sum,
		Score:         math.Min(100, sum),
		WindowStartUS: event.TimestampUS - windowUS,
		WindowEndUS:   event.TimestampUS,
		Backend:       "redis",
	}, nil
}

func parseWindowResult(result any) (int, float64) {
	values, ok := result.([]any)
	if !ok || len(values) < 2 {
		return 0, 0
	}
	count := 0
	switch value := values[0].(type) {
	case int64:
		count = int(value)
	case float64:
		count = int(value)
	case string:
		fmt.Sscanf(value, "%d", &count)
	}
	sum := 0.0
	switch value := values[1].(type) {
	case int64:
		sum = float64(value)
	case float64:
		sum = value
	case string:
		fmt.Sscanf(value, "%f", &sum)
	}
	if math.IsNaN(sum) || math.IsInf(sum, 0) {
		sum = 0
	}
	return count, sum
}
