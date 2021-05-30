// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"strings"

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
			gw, err := GetDefaultIpv4GatewayByLink(link.Attrs().Index)
			if err != nil {
				gw, err = GetDefaultIpv4Gateway()
				if err != nil {
					return err
				}
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
