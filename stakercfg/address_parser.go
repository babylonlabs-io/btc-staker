// This file is derived from the lnd repository (https://github.com/lightningnetwork/lnd/blob/master/lncfg/address.go),
// original copyright: Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers

package stakercfg

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

type TCPResolver = func(network, addr string) (*net.TCPAddr, error)

// verifyPort makes sure that an address string has both a host and a port. If
// there is no port found, the default port is appended. If the address is just
// a port, then we'll assume that the user is using the short cut to specify a
// localhost:port address.
func verifyPort(address string, defaultPort string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// If the address itself is just an integer, then we'll assume
		// that we're mapping this directly to a localhost:port pair.
		// This ensures we maintain the legacy behavior.
		if _, err := strconv.Atoi(address); err == nil {
			return net.JoinHostPort("localhost", address)
		}

		// Otherwise, we'll assume that the address just failed to
		// attach its own port, so we'll use the default port. In the
		// case of IPv6 addresses, if the host is already surrounded by
		// brackets, then we'll avoid using the JoinHostPort function,
		// since it will always add a pair of brackets.
		if strings.HasPrefix(address, "[") {
			return address + ":" + defaultPort
		}
		return net.JoinHostPort(address, defaultPort)
	}

	// In the case that both the host and port are empty, we'll use the
	// default port.
	if host == "" && port == "" {
		return ":" + defaultPort
	}

	return address
}

func IsLoopback(host string) bool {
	if strings.Contains(host, "localhost") {
		return true
	}

	rawHost, _, _ := net.SplitHostPort(host)
	addr := net.ParseIP(rawHost)
	if addr == nil {
		return false
	}

	return addr.IsLoopback()
}

// isIPv6Host returns true if the host is IPV6 and false otherwise.
func isIPv6Host(host string) bool {
	v6Addr := net.ParseIP(host)
	if v6Addr == nil {
		return false
	}

	// The documentation states that if the IP address is an IPv6 address,
	// then To4() will return nil.
	return v6Addr.To4() == nil
}

// isUnspecifiedHost returns true if the host IP is considered unspecified.
func isUnspecifiedHost(host string) bool {
	addr := net.ParseIP(host)
	if addr == nil {
		return false
	}

	return addr.IsUnspecified()
}

func ParseAddressString(strAddress string, defaultPort string,
	tcpResolver TCPResolver) (net.Addr, error) {
	var parsedNetwork, parsedAddr string

	// Addresses can either be in network://address:port format,
	// network:address:port, address:port, or just port. We want to support
	// all possible types.
	if strings.Contains(strAddress, "://") {
		parts := strings.Split(strAddress, "://")
		parsedNetwork, parsedAddr = parts[0], parts[1]
	} else if strings.Contains(strAddress, ":") {
		parts := strings.Split(strAddress, ":")
		parsedNetwork = parts[0]
		parsedAddr = strings.Join(parts[1:], ":")
	}

	// Only TCP and Unix socket addresses are valid. We can't use IP or
	// UDP only connections for anything we do in lnd.
	switch parsedNetwork {
	case "unix", "unixpacket":
		return net.ResolveUnixAddr(parsedNetwork, parsedAddr)

	case "tcp", "tcp4", "tcp6":
		return tcpResolver(
			parsedNetwork, verifyPort(parsedAddr, defaultPort),
		)

	case "ip", "ip4", "ip6", "udp", "udp4", "udp6", "unixgram":
		return nil, fmt.Errorf("only TCP or unix socket "+
			"addresses are supported: %s", parsedAddr)

	default:
		// We'll now possibly apply the default port, use the local
		// host short circuit, or parse out an all interfaces listen.
		addrWithPort := verifyPort(strAddress, defaultPort)
		rawHost, _, _ := net.SplitHostPort(addrWithPort)

		// Otherwise, we'll attempt the resolve the host. The Tor
		// resolver is unable to resolve local addresses,
		// IPv6 addresses, or the all-interfaces address, so we'll use
		// the system resolver instead for those.
		if rawHost == "" || IsLoopback(rawHost) ||
			isIPv6Host(rawHost) || isUnspecifiedHost(rawHost) {
			return net.ResolveTCPAddr("tcp", addrWithPort)
		}

		// If we've reached this point, then it's possible that this
		// resolve returns an error if it isn't able to resolve the
		// host. For example, local entries in /etc/hosts will fail to
		// be resolved by Tor. In order to handle this case, we'll fall
		// back to the normal system resolver if we fail with an
		// identifiable error.
		addr, err := tcpResolver("tcp", addrWithPort)
		if err != nil {
			torErrStr := "tor host is unreachable"
			if strings.Contains(err.Error(), torErrStr) {
				return net.ResolveTCPAddr("tcp", addrWithPort)
			}

			return nil, err
		}

		return addr, nil
	}
}

func NormalizeAddresses(addrs []string, defaultPort string,
	tcpResolver TCPResolver) ([]net.Addr, error) {
	result := make([]net.Addr, 0, len(addrs))
	seen := map[string]struct{}{}

	for _, addr := range addrs {
		parsedAddr, err := ParseAddressString(
			addr, defaultPort, tcpResolver,
		)
		if err != nil {
			return nil, fmt.Errorf("parse address %s failed: %w",
				addr, err)
		}

		if _, ok := seen[parsedAddr.String()]; !ok {
			result = append(result, parsedAddr)
			seen[parsedAddr.String()] = struct{}{}
		}
	}

	return result, nil
}
