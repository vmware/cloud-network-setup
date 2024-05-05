// Copyright 2024 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"net"
	"strconv"

	"github.com/pkg/errors"
)

func ParseIp(ip string) (net.IP, error) {
	a := net.ParseIP(ip)
	if a.To4() == nil || a.To16() == nil {
		return nil, errors.New("invalid IP")
	}

	return a, nil
}

func ParsePort(port string) (uint16, error) {
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, errors.Wrap(err, "invalid port")
	}

	return uint16(p), nil
}

func ParseIpPort(s string) (string, string, error) {
	ip, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", "", err
	}

	if _, err := ParseIp(ip); err != nil {
		return "", "", errors.New("invalid IP")
	}

	if _, err := ParsePort(port); err != nil {
		return "", "", errors.New("invalid port")
	}

	return ip, port, nil
}

// Splits MAC address without ':' or '-' into MAC address format by inserting ':'
func ParseMAC(s string) string {
	for i := 2; i < len(s); i += 3 {
		s = s[:i] + ":" + s[i:]
	}

	return s
}
