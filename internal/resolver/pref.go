package resolver

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Preferred-IP cache: racing a name costs probes on every cache miss, so
// the winner of a race is remembered per (name, qtype) in Redis
// (dns:pref:<name>:<type>) and later resolutions reuse it directly
// instead of racing again.
//
// An entry is only ever a narrowing hint: it applies when the remembered
// IP still appears in the upstream's current answer — the answer itself
// always comes from the upstream. The entry's hit counter doubles as the
// revalidation throttle: once it reaches recheckHits, or the entry ages
// past recheckAge, the next resolution races again and refreshes it, so
// a winner that went slow is eventually replaced.
//
// A race with no finisher is remembered too, as a negative entry with an
// empty IP and a short lifetime: names whose addresses answer nothing
// (the common case for non-web services before ICMP fallback existed, or
// firewalled hosts) then skip straight past the race until it expires.

// PrefEntry is one remembered race outcome.
type PrefEntry struct {
	IP      net.IP // nil = negative entry (recent race had no finisher)
	Via     string // how the winner won: "tcp/443", "tcp/80", "icmp"
	RTT     time.Duration
	Hits    int64
	Updated time.Time
}

// PrefBackend is the storage behind the preferred-IP cache.
type PrefBackend interface {
	LoadPref(ctx context.Context, key string) (*PrefEntry, error)
	StorePref(ctx context.Context, key string, e *PrefEntry, ttl time.Duration) error
	BumpPref(ctx context.Context, key string) error
}

// prefState bundles the backend with the cache's tuning.
type prefState struct {
	backend     PrefBackend
	ttl         time.Duration // lifetime of a positive entry
	negTTL      time.Duration // lifetime of a negative entry
	recheckHits int64         // hits after which a fresh race is due
	recheckAge  time.Duration // age after which a fresh race is due
}

// prefOpTimeout bounds every pref storage operation: the cache is an
// optimisation, never something a resolution should wait on.
const prefOpTimeout = 250 * time.Millisecond

// EnablePref turns on the preferred-IP cache over backend. Non-positive
// tuning values take defaults (24h positive TTL, 10m negative TTL,
// recheck after 100 hits or 6h).
func (r *Resolver) EnablePref(b PrefBackend, ttl, negTTL time.Duration, recheckHits int64, recheckAge time.Duration) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if negTTL <= 0 {
		negTTL = 10 * time.Minute
	}
	if recheckHits <= 0 {
		recheckHits = 100
	}
	if recheckAge <= 0 {
		recheckAge = 6 * time.Hour
	}
	r.pref = &prefState{backend: b, ttl: ttl, negTTL: negTTL, recheckHits: recheckHits, recheckAge: recheckAge}
}

func prefKey(name string, qtype uint16) string {
	return "dns:pref:" + name + ":" + dns.Type(qtype).String()
}

// applyPref consults the preferred-IP cache for this answer. When it
// returns done=true, out is the final message (narrowed to the preferred
// IP, or untouched for a negative entry) and no race must run.
func (r *Resolver) applyPref(msg *dns.Msg, qtype uint16, name string, ips []net.IP) (out *dns.Msg, done bool) {
	if r.pref == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), prefOpTimeout)
	defer cancel()
	e, err := r.pref.backend.LoadPref(ctx, prefKey(name, qtype))
	if err != nil || e == nil {
		return nil, false
	}
	if e.IP == nil {
		// Negative entry: presence is enough, its storage TTL bounds
		// how long the "nobody answers" verdict is trusted.
		log.Printf("resolver: pref name=%s type=%d negative hit, keeping upstream answer", name, qtype)
		return msg, true
	}
	if e.Hits >= r.pref.recheckHits || time.Since(e.Updated) > r.pref.recheckAge {
		return nil, false // due a revalidation race
	}
	if !ipIn(ips, e.IP) {
		return nil, false // winner rotated out of the answer: re-race
	}
	_ = r.pref.backend.BumpPref(ctx, prefKey(name, qtype))
	log.Printf("resolver: pref name=%s type=%d hit ip=%s via=%s hits=%d, skipping race",
		name, qtype, e.IP, e.Via, e.Hits+1)
	return narrow(msg, qtype, e.IP), true
}

// storePref records a race outcome: the winner (positive entry) or, with
// a nil IP, the fact that nobody answered (negative entry).
func (r *Resolver) storePref(name string, qtype uint16, ip net.IP, via string, rtt time.Duration) {
	if r.pref == nil {
		return
	}
	ttl := r.pref.ttl
	if ip == nil {
		ttl = r.pref.negTTL
	}
	e := &PrefEntry{IP: ip, Via: via, RTT: rtt, Hits: 1, Updated: time.Now()}
	ctx, cancel := context.WithTimeout(context.Background(), prefOpTimeout)
	defer cancel()
	_ = r.pref.backend.StorePref(ctx, prefKey(name, qtype), e, ttl)
}
