// Package proto defines the payloads exchanged between the LAN-side client
// and the server-side resolver over Redis.
package proto

// Request is a DNS resolution request the client publishes to the request
// stream (dns:req) for the server to consume.
type Request struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

// Response is the answer to a single Request, delivered on the response
// stream (dns:resp). The client matches it to its pending request by ID.
//
// Wire carries the packed DNS response message (dns.Msg.Pack) verbatim, so the
// client can replay exactly what upstream returned — rcode, TTLs, and all
// sections — without any lossy re-encoding.
//
// ResolvedAt is the server's wall-clock timestamp (Unix nanoseconds) for this
// answer. The client uses it as a version to order competing writes to its
// local cache (on-demand responses vs. pushed updates).
type Response struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       uint16 `json:"type"`
	Rcode      int    `json:"rcode"`
	ResolvedAt int64  `json:"resolved_at"`
	Wire       []byte `json:"wire,omitempty"`
	Err        string `json:"err,omitempty"`
}

// Update is a broadcast pushed by the server on the pub/sub channel
// (dns:updates) whenever a name is freshly resolved, so every subscribing
// client can warm its local cache without issuing its own request. Losing an
// Update is harmless: the client falls back to on-demand resolution.
type Update struct {
	Name       string `json:"name"`
	Type       uint16 `json:"type"`
	Rcode      int    `json:"rcode"`
	ResolvedAt int64  `json:"resolved_at"`
	Wire       []byte `json:"wire,omitempty"`
}
