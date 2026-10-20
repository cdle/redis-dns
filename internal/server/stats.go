package server

import (
	"context"
	"log"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"

	"github.com/imdraw/redis-dns/internal/redisx"
)

// Query counting and dynamic prefetch.
//
// Counting fixed hot domains by hand (dns:hot:domains) only ever warms
// what someone remembered to list. Instead the server counts every
// client request into a sorted set (dns:count:q, member "<fqdn>|<type>",
// score = query count) and the prefetch sweep keeps the top-N members
// warm: popularity decides what gets prefetched, not a fixed list.
//
// Counting happens in handle(), which only ever sees client requests —
// prefetch resolves through a separate path — so prefetched names
// cannot inflate their own scores.
//
// Scores decay exponentially (half-life 24h by default): each sweep
// multiplies every score by 0.5^(sweep/half-life), and members that
// decay below pruneBelowScore are dropped, so last month's fad ages out
// of the ranking while a steady one query an hour stays ranked. The set
// is hard-capped at maxCountMembers members.

const (
	// minPrefetchScore is the decayed count a name needs to qualify
	// for dynamic prefetch: a single one-off query never qualifies.
	minPrefetchScore = 2.0
	// pruneBelowScore drops members whose decayed count falls under
	// this line during a sweep.
	pruneBelowScore = 0.5
	// maxCountMembers caps the ranking set; the lowest-ranked members
	// beyond the cap are dropped during a sweep.
	maxCountMembers = 10000
	// countQueueSize bounds the queue between the query path and
	// the counter goroutine; when it is full, counts are dropped
	// rather than ever slowing a query down.
	countQueueSize = 4096
)

// countMember renders the sorted-set member for a queried name.
func countMember(name string, qtype uint16) string {
	return strings.ToLower(dns.Fqdn(name)) + "|" + dns.Type(qtype).String()
}

// parseMember splits a sorted-set member back into name and query type.
func parseMember(m string) (string, uint16, bool) {
	i := strings.LastIndex(m, "|")
	if i <= 0 || i == len(m)-1 {
		return "", 0, false
	}
	t, ok := dns.StringToType[m[i+1:]]
	if !ok {
		return "", 0, false
	}
	return m[:i], t, true
}

// decayFactor returns the multiplier for scores after elapsed with the
// given half-life: 0.5^(elapsed/halfLife).
func decayFactor(halfLife, elapsed time.Duration) float64 {
	if halfLife <= 0 || elapsed <= 0 {
		return 1
	}
	return math.Pow(0.5, float64(elapsed)/float64(halfLife))
}

// prefetchNextDelay schedules a dynamic entry's next refresh at 80% of
// the answer's cache TTL — soon enough that the entry never lapses,
// never more often than the sweep itself, never rarer than hourly.
func prefetchNextDelay(ttl, sweep time.Duration) time.Duration {
	if ttl <= 0 {
		return sweep
	}
	d := ttl * 4 / 5
	if d < sweep {
		d = sweep
	}
	if d > time.Hour {
		d = time.Hour
	}
	return d
}

// scoredMember is one ranked member of the query-count set.
type scoredMember struct {
	Member string
	Score  float64
}

// rankStore is the storage behind query counting: a ranked set of
// queried names. The production implementation is Redis; tests use a
// fake.
type rankStore interface {
	Top(ctx context.Context, n int, minScore float64) ([]scoredMember, error)
	Decay(ctx context.Context, factor float64) error
}

// redisRankStore implements rankStore over the query-count sorted set.
type redisRankStore struct {
	rdb *redis.Client
}

func (s *redisRankStore) Top(ctx context.Context, n int, minScore float64) ([]scoredMember, error) {
	zs, err := s.rdb.ZRevRangeByScoreWithScores(ctx, redisx.SetQueryCounts, &redis.ZRangeBy{
		Min:   strconv.FormatFloat(minScore, 'f', -1, 64),
		Max:   "+inf",
		Count: int64(n),
	}).Result()
	if err != nil {
		return nil, err
	}
	out := make([]scoredMember, 0, len(zs))
	for _, z := range zs {
		out = append(out, scoredMember{Member: z.Member, Score: z.Score})
	}
	return out, nil
}

func (s *redisRankStore) Decay(ctx context.Context, factor float64) error {
	if factor >= 1 || factor <= 0 {
		return nil
	}
	pipe := s.rdb.Pipeline()
	pipe.ZUnionStore(ctx, redisx.SetQueryCounts, &redis.ZStore{
		Keys:    []string{redisx.SetQueryCounts},
		Weights: []float64{factor},
	})
	pipe.ZRemRangeByScore(ctx, redisx.SetQueryCounts, "-inf",
		strconv.FormatFloat(pruneBelowScore, 'f', -1, 64))
	pipe.ZRemRangeByRank(ctx, redisx.SetQueryCounts, 0, -maxCountMembers-1)
	_, err := pipe.Exec(ctx)
	return err
}

// countQuery records one client request in the ranking set. The
// write itself is handed to the counter goroutine (runCounter):
// the query path only renders the member and makes a non-blocking
// channel send, dropping the count when the queue is full —
// statistics must never delay an answer.
func (s *Server) countQuery(_ context.Context, name string, qtype uint16) {
	if s.countCh == nil {
		return
	}
	select {
	case s.countCh <- countMember(name, qtype):
	default:
	}
}

// runCounter is the single goroutine that owns query-count writes.
// It receives members from countCh and folds them into the ranking
// set in small pipelined batches — flushed when a batch fills, on
// a short ticker, and once more on shutdown — so the Redis writes
// happen entirely off the query path.
func (s *Server) runCounter(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	var batch []string
	flush := func() {
		if len(batch) == 0 {
			return
		}
		wctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		pipe := s.rdb.Pipeline()
		for _, m := range batch {
			pipe.ZIncrBy(wctx, redisx.SetQueryCounts, 1, m)
		}
		if _, err := pipe.Exec(wctx); err != nil {
			log.Printf("server: count flush (%d): %v", len(batch), err)
		}
		batch = batch[:0]
	}
	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case m := <-s.countCh:
			batch = append(batch, m)
			if len(batch) >= 256 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// dueDynamic filters ranked members down to those the sweep should
// refresh now: parseable, and not already scheduled for later.
func dueDynamic(top []scoredMember, next map[string]time.Time, now time.Time) []scoredMember {
	var due []scoredMember
	for _, m := range top {
		if _, _, ok := parseMember(m.Member); !ok {
			continue
		}
		if t, ok := next["dyn|"+m.Member]; ok && now.Before(t) {
			continue
		}
		due = append(due, m)
	}
	return due
}
