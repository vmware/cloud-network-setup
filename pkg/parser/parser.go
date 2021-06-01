// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"errors"
	"net"
	"strconv"
)

func ParseIP(ip string) (net.IP, error) {
	if len(ip) == 0 {
		return nil, errors.New("invalid")
	}

	a := net.ParseIP(ip)

	if a.To4() == nil || a.To16() == nil {
		return nil, errors.New("invalid")
	}

	return a, nil
}

func ParsePort(port string) (uint16, error) {
	if len(port) == 0 {
		return 0, nil
	}

	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, err
	}

	return uint16(p), nil
}

// Splits MAC address without ':' or '-' into MAC address format by inserting ':'
func ParseMAC(s string) string {
	for i := 2; i < len(s); i += 3 {
		s = s[:i] + ":" + s[i:]
	}

	return s
}
