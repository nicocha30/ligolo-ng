// Ligolo-ng Relay
// Copyright (C) 2025 Nicolas Chatelain (nicocha30)

package netstack

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/checksum"
	"github.com/nicocha30/gvisor-ligolo/pkg/tcpip/header"
)

func TestBuildICMPv4PortUnreachable(t *testing.T) {
	scanner := tcpip.AddrFrom4([4]byte{10, 0, 0, 5})
	target := tcpip.AddrFrom4([4]byte{10, 0, 0, 1})
	const scannerPort, targetPort = 44444, 53

	// The embedded original datagram travelled scanner -> target.
	icmpHdr := buildICMPv4PortUnreachable(scanner, target, scannerPort, targetPort)

	if got := icmpHdr.Type(); got != header.ICMPv4DstUnreachable {
		t.Errorf("Type = %d, want %d (DstUnreachable)", got, header.ICMPv4DstUnreachable)
	}
	if got := icmpHdr.Code(); got != header.ICMPv4PortUnreachable {
		t.Errorf("Code = %d, want %d (PortUnreachable)", got, header.ICMPv4PortUnreachable)
	}
	// A correct ICMP checksum makes the one's-complement sum of the whole message 0xffff.
	if sum := checksum.Checksum(icmpHdr, 0); sum != 0xffff {
		t.Errorf("checksum invalid: full-message sum = %#x, want 0xffff", sum)
	}

	// Embedded original IPv4 header follows the 8-byte ICMP header.
	embIP := header.IPv4(icmpHdr[header.ICMPv4MinimumSize:])
	if embIP.SourceAddress() != scanner {
		t.Errorf("embedded src = %v, want %v", embIP.SourceAddress(), scanner)
	}
	if embIP.DestinationAddress() != target {
		t.Errorf("embedded dst = %v, want %v", embIP.DestinationAddress(), target)
	}
	if embIP.Protocol() != uint8(header.UDPProtocolNumber) {
		t.Errorf("embedded protocol = %d, want %d (UDP)", embIP.Protocol(), header.UDPProtocolNumber)
	}

	// Embedded first 8 bytes = UDP header.
	udp := icmpHdr[header.ICMPv4MinimumSize+header.IPv4MinimumSize:]
	if sp := binary.BigEndian.Uint16(udp[0:2]); sp != scannerPort {
		t.Errorf("embedded UDP src port = %d, want %d", sp, scannerPort)
	}
	if dp := binary.BigEndian.Uint16(udp[2:4]); dp != targetPort {
		t.Errorf("embedded UDP dst port = %d, want %d", dp, targetPort)
	}
}

func TestICMPRateLimiter(t *testing.T) {
	limiter := newICMPRateLimiter(time.Second)
	current := time.Unix(100, 0)
	limiter.now = func() time.Time { return current }

	if !limiter.allow("target>scanner") {
		t.Fatal("first packet should be allowed")
	}
	if limiter.allow("target>scanner") {
		t.Fatal("second packet inside interval should be rate-limited")
	}
	if !limiter.allow("other-target>scanner") {
		t.Fatal("separate flow should be allowed")
	}

	current = current.Add(time.Second)
	if !limiter.allow("target>scanner") {
		t.Fatal("packet after interval should be allowed")
	}
}

func TestICMPRateLimiterDisabled(t *testing.T) {
	limiter := newICMPRateLimiter(0)
	if !limiter.allow("target>scanner") || !limiter.allow("target>scanner") {
		t.Fatal("disabled limiter should allow every packet")
	}
}

func TestBuildICMPv6PortUnreachable(t *testing.T) {
	scanner := tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05})
	target := tcpip.AddrFrom16([16]byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01})
	const scannerPort, targetPort = 44444, 53

	// outerSrc=target, outerDst=scanner (error goes target -> scanner);
	// embedded datagram travelled scanner -> target.
	icmpHdr := buildICMPv6PortUnreachable(target, scanner, scanner, target, scannerPort, targetPort)

	if got := icmpHdr.Type(); got != header.ICMPv6DstUnreachable {
		t.Errorf("Type = %d, want %d (DstUnreachable)", got, header.ICMPv6DstUnreachable)
	}
	if got := icmpHdr.Code(); got != header.ICMPv6PortUnreachable {
		t.Errorf("Code = %d, want %d (PortUnreachable)", got, header.ICMPv6PortUnreachable)
	}
	// Verify the checksum is internally consistent: recomputing over the message
	// with the same pseudo-header must reproduce the stored value.
	stored := icmpHdr.Checksum()
	recomputed := header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header: icmpHdr,
		Src:    target,
		Dst:    scanner,
	})
	// ICMPv6Checksum returns the value with the checksum field treated as 0, so
	// compare against the stored checksum.
	icmpHdr.SetChecksum(0)
	if recomputed != stored {
		t.Errorf("checksum = %#x, recomputed = %#x", stored, recomputed)
	}
	icmpHdr.SetChecksum(stored)

	// Embedded original IPv6 header follows the 8-byte ICMPv6 header.
	embIP := header.IPv6(icmpHdr[header.ICMPv6MinimumSize:])
	if embIP.SourceAddress() != scanner {
		t.Errorf("embedded src = %v, want %v", embIP.SourceAddress(), scanner)
	}
	if embIP.DestinationAddress() != target {
		t.Errorf("embedded dst = %v, want %v", embIP.DestinationAddress(), target)
	}

	udp := icmpHdr[header.ICMPv6MinimumSize+header.IPv6MinimumSize:]
	if sp := binary.BigEndian.Uint16(udp[0:2]); sp != scannerPort {
		t.Errorf("embedded UDP src port = %d, want %d", sp, scannerPort)
	}
	if dp := binary.BigEndian.Uint16(udp[2:4]); dp != targetPort {
		t.Errorf("embedded UDP dst port = %d, want %d", dp, targetPort)
	}
}
