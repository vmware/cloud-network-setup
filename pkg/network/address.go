// Copyright 2024 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"github.com/vishvananda/netlink"
)

func AddressAddress(ifIndex int, address string) error {
	link, err := netlink.LinkByIndex(ifIndex)
	if err != nil {
		return err
	}

	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return err
	}

	if err := netlink.AddrAdd(link, addr); err != nil && err.Error() != "file exists" {
		return err
	}

	return nil
}

func AddressSet(name string, address string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}

	addr, err := netlink.ParseAddr(address)
	if err != nil {
		return err
	}

	if err := netlink.AddrReplace(link, addr); err != nil {
		return nil
	}

	return nil
}

func GetIPv4Addresses(ifName string) (map[string]bool, error) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, err
	}

	addresses, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	m := make(map[string]bool)
	for _, addr := range addresses {
		m[addr.IPNet.String()] = true
	}

	return m, nil
}

func AddressRemove(ifName string, address string) error {
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
