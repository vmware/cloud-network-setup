// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package network

import (
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type Links struct {
	LinksByMAC map[string]Link
}

// Link Each interface info
type Link struct {
	Name      string
	Ifindex   int
	OperState string
	Mac       string
	MTU       int
	Addresses *map[string]bool
}

// AcquireLinks Fetches link information
func AcquireLinks() (Links, error) {
	links := make(map[string]Link)

	linkList, err := netlink.LinkList()
	if err != nil {
		return Links{}, err
	}

	for _, link := range linkList {
		if link.Attrs().Name == "lo" {
			continue
		}

		l := Link{
			Name:      link.Attrs().Name,
			Ifindex:   link.Attrs().Index,
			Mac:       link.Attrs().HardwareAddr.String(),
			OperState: link.Attrs().OperState.String(),
			MTU:       link.Attrs().MTU,
		}

		links[link.Attrs().HardwareAddr.String()] = l

		log.Debugf("Acquired link='%+v' ifindex='%+v'", link.Attrs().Name, link.Attrs().Index)
	}

	return Links{
		LinksByMAC: links,
	}, nil
}

func SetLinkOperStateUp(ifIndex int) error {
	linkList, err := netlink.LinkList()
	if err != nil {
		return err
	}

	for _, link := range linkList {
		if link.Attrs().Index == ifIndex {
			err := netlink.LinkSetUp(link)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func SetLinkMtu(ifIndex int, mtu int) error {
	linkList, err := netlink.LinkList()
	if err != nil {
		return err
	}

	for _, link := range linkList {
		if link.Attrs().Index == ifIndex {
			err := netlink.LinkSetMTU(link, mtu)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
