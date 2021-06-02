// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func ConfigureByIndex(ifIndex int) error {
	linkList, err := netlink.LinkList()
	if err != nil {
		return err
	}

	for _, link := range linkList {
		if link.Attrs().Name == "lo" {
			continue
		}

		if link.Attrs().Index == ifIndex {
			gw, err := GetIpv4Gateway(link.Attrs().Index)
			if err != nil {
				return err
			}

			err = AddRoute(link.Attrs().Index, ROUTE_TABLE_BASE+link.Attrs().Index, gw)
			if err != nil {
				return err
			}

			addresses, err := GetIPv4Addresses(link.Attrs().Name)
			if err != nil {
				return err
			}

			for addr := range addresses {
				a := strings.TrimSuffix(strings.SplitAfter(addr, "/")[0], "/")

				from := &IPRoutingRule{
					From:  a,
					Table: ROUTE_TABLE_BASE + link.Attrs().Index,
				}

				if err := AddRoutingPolicyRule(from); err != nil {
					return err
				}
			}
			break
		}
	}

	return nil
}

// When both links in same subnet
func ConfigureSupplementaryLinks(s string) error {
	words := strings.Fields(s)
	if len(words) <= 0 {
		return nil
	}

	for _, w := range words {
		link, err := net.InterfaceByName(w)
		if err != nil {
			log.Debugf("Failed to find link='%s'. Ignoring ...: %+v", w, err)
			continue
		}

		if err = ConfigureByIndex(link.Index); err != nil {
			log.Errorf("Failed to configure network for link='%s' ifindex='%d': %+v", link.Name, link.Index, err)
			return err
		}

		log.Debugf("Successfully configured network for link='%s' ifindex='%d'", link.Name, link.Index)
	}

	return nil
}

func GetIpv4Gateway(ifIndex int) (string, error) {
	gw, err := GetDefaultIpv4GatewayByLink(ifIndex)
	if err != nil {
		gw, err = GetIpv4GatewayByLink(ifIndex)
		if err != nil {
			// Try Harder ?
			gw, err = GetDefaultIpv4Gateway()
			if err != nil {
				return "", err
			}
		}
	}

	return gw, nil
}
