// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"github.com/vishvananda/netlink"
)

func AddAddress(ifIndex int, address string) error {
	link, err := netlink.LinkByIndex(ifIndex)
	if err != nil {
		return err
	}

	a, err := netlink.ParseAddr(address)
	if err != nil {
		return err
	}

	if err := netlink.AddrAdd(link, a); err != nil && err.Error() != "file exists" {
		return err
	}

	return nil
}

func SetAddress(name string, address string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}

	a, err := netlink.ParseAddr(address)
	if err != nil {
		return err
	}

	if err := netlink.AddrReplace(link, a); err != nil {
		return nil
	}

	return nil
}

func GetIPv4Addresses(ifName string) (map[string]bool, error) {
	m := make(map[string]bool)

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, err
	}

	addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	} else {
		for _, addr := range addresses {
			m[addr.IPNet.String()] = true
		}
	}
	return m, nil
}

func RemoveIPAddress(ifName string, address string) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return err
	}

	if err := netlink.AddrDel(link, addr); err != nil {
		return nil
	}

	return nil
}
