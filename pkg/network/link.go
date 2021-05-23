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
func AcquireLinks() (*Links, error) {
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

		log.Debugf("Aquired link='%+v' ifindex='%+v'", link.Attrs().Name, link.Attrs().Index)
	}

	return &Links{
		LinksByMAC: links,
	}, nil
}
