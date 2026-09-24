// Package proto defines the payloads exchanged between the LAN-side client
// and the server-side resolver over Redis.
package proto

// Request is a DNS resolution request published to the request stream.
type Request struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

// Response is the resolution result delivered back to the client.
//
// Wire carries the packed DNS response message (dns.Msg.Pack) verbatim, so the
// client can replay exactly what upstream returned — rcode, TTLs, and all
// sections — without any lossy re-encoding.
type Response struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Rcode int    `json:"rcode"`
	Wire  []byte `json:"wire,omitempty"`
	Err   string `json:"err,omitempty"`
}
