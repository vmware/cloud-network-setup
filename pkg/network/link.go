// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type Links struct {
	LinksByMAC map[string]Link
}

// Link Each interface info
type Link struct {
	Name         string
	Ifindex      int
	HardwareAddr net.HardwareAddr
}

// AcquireLinks Fetches link information
func AcquireLinksFromKernel() (*Links, error) {
	links := make(map[string]Link)

	linkList, err := netlink.LinkList()
	if err != nil {
		return nil, err
	}

	for _, link := range linkList {
		if link.Attrs().Name == "lo" {
			continue
		}

		l := Link{
			Name:         link.Attrs().Name,
			Ifindex:      link.Attrs().Index,
			HardwareAddr: link.Attrs().HardwareAddr,
		}

		links[link.Attrs().HardwareAddr.String()] = l

		log.Infof("Aquired link='%+v' ifindex='%+v'", link.Attrs().Name, link.Attrs().Index)
	}

	return &Links{
		LinksByMAC: links,
	}, nil
}

// AddAddress Add address to link
func AddAddress(ifIndex int, addr string, prefix int) error {
	link, err := netlink.LinkByIndex(ifIndex)
	if err != nil {
		return err
	}

	ip := &netlink.Addr{IPNet: &net.IPNet{
		IP:   net.ParseIP(addr),
		Mask: net.CIDRMask(prefix, 32),
	}}

	if err := netlink.AddrAdd(link, ip); err != nil && err.Error() != "file exists" {
		return err
	}

	log.Infof("Successfully added address='%+v on link='%+v' ifindex='%d'", addr, link.Attrs().Name, link.Attrs().Index)
	return nil
}
