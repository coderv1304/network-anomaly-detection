package state

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const redisWindowScript = `
local key = KEYS[1]
local member = ARGV[1]
local risk = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local window = tonumber(ARGV[4])
local expire = tonumber(ARGV[5])
redis.call('ZADD', key, risk, member)
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window)
redis.call('EXPIRE', key, expire)
local entries = redis.call('ZRANGE', key, 0, -1, 'WITHSCORES')
local total = 0
for i = 2, #entries, 2 do
  total = total + tonumber(entries[i])
end
return {#entries / 2, total}
`

type redisAccumulator struct {
	client   *redis.Client
	windowS  float64
	fallback *memoryAccumulator
	logger   *slog.Logger
	healthy  atomic.Bool
}

func newRedisAccumulator(ctx context.Context, redisURL string, window time.Duration, fallback *memoryAccumulator, logger *slog.Logger) (*redisAccumulator, error) {
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
	acc := &redisAccumulator{
		client:   client,
		windowS:  window.Seconds(),
		fallback: fallback,
		logger:   logger,
	}
	acc.healthy.Store(true)
	return acc, nil
}

func (a *redisAccumulator) Backend() string {
	if a.healthy.Load() {
		return "redis"
	}
	return "memory"
}

func (a *redisAccumulator) Close() error {
	return a.client.Close()
}

func (a *redisAccumulator) Record(ctx context.Context, event Event) (WindowSnapshot, error) {
	if event.SourceIP == "" {
		return WindowSnapshot{}, nil
	}
	nowSeconds := float64(event.TimestampUS) / 1e6
	member := event.FlowID
	if member == "" {
		member = fmt.Sprintf("%d|%s", event.TimestampUS, event.Label)
	}
	callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	result, err := a.client.Eval(
		callCtx,
		redisWindowScript,
		[]string{"netshield:win:" + event.SourceIP},
		member,
		clampRisk(event.Risk),
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
