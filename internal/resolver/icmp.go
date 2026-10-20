package resolver

import (
	"context"
	"net"
	"os"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// icmpSeq varies the echo identifier per probe so concurrent races on
// raw sockets can tell their replies apart.
var icmpSeq uint32

// icmpPing measures the ICMP echo round-trip to ip. Echoes are resent
// every icmpRetry until one is answered or ctx ends, so a single dropped
// packet does not disqualify a healthy address. It prefers a raw socket
// and falls back to an unprivileged ping socket when raw is not
// permitted; if neither can be opened the probe simply fails and racing
// carries on without ICMP.
func icmpPing(ctx context.Context, ip net.IP) (time.Duration, error) {
	v4 := ip.To4() != nil
	rawNet, udpNet, proto := "ip4:icmp", "udp4", 1 // 1 = ICMP, 58 = ICMPv6
	reqType, replyType := ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
	if !v4 {
		rawNet, udpNet, proto = "ip6:ipv6-icmp", "udp6", 58
		reqType, replyType = ipv4.ICMPType(ipv6.ICMPTypeEchoRequest), ipv4.ICMPType(ipv6.ICMPTypeEchoReply)
	}
	conn, err := icmp.ListenPacket(rawNet, "")
	raw := true
	if err != nil {
		raw = false
		conn, err = icmp.ListenPacket(udpNet, "")
		if err != nil {
			return 0, err
		}
	}
	defer func() { _ = conn.Close() }()

	var dst net.Addr
	if raw {
		dst = &net.IPAddr{IP: ip}
	} else {
		dst = &net.UDPAddr{IP: ip}
	}
	id := (os.Getpid() + int(atomic.AddUint32(&icmpSeq, 1))) & 0xffff

	buf := make([]byte, 1500)
	for seq := 1; ; seq++ {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		wire, err := (&icmp.Message{
			Type: reqType,
			Code: 0,
			Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("redis-dns race probe")},
		}).Marshal(nil)
		if err != nil {
			return 0, err
		}
		sent := time.Now()
		if _, err := conn.WriteTo(wire, dst); err != nil {
			return 0, err
		}
		wait := 150 * time.Millisecond
		if dl, ok := ctx.Deadline(); ok {
			if rem := time.Until(dl); rem < wait {
				wait = rem
			}
		}
		_ = conn.SetReadDeadline(time.Now().Add(wait))
		for {
			n, _, err := conn.ReadFrom(buf)
			if err != nil {
				break // timed out: resend with the next sequence
			}
			rm, err := icmp.ParseMessage(proto, buf[:n])
			if err != nil || rm.Type != replyType {
				continue
			}
			echo, ok := rm.Body.(*icmp.Echo)
			if !ok || echo.Seq != seq {
				continue
			}
			// On ping sockets the kernel owns the identifier and only
			// delivers our replies; on raw sockets match it ourselves.
			if raw && echo.ID != id {
				continue
			}
			return time.Since(sent), nil
		}
	}
}
