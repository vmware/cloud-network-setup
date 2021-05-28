// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package network

import (
	"net"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type IPRoutingRule struct {
	Address string
	Prefix  int
	Table   int
}

func AddRoutingPolicyRule(rule *IPRoutingRule) error {
	links, err := netlink.LinkList()
	if err != nil {
		return nil
	}

	// If single link the we don't need to configure additional routing policy rules
	if len(links) <= 2 {
		return nil
	}

	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return err
	}

	r := netlink.NewRule()
	r.Table = rule.Table
	r.Src = &net.IPNet{IP: net.ParseIP(rule.Address), Mask: net.CIDRMask(rule.Prefix, 32)}

	// find this rule
	found := ruleExists(rules, *r)
	if found {
		log.Debugf("Routing table rules already configured address='%+v' table='%v'", rule.Address, rule.Address)
		return nil
	}

	if err = netlink.RuleAdd(r); err != nil {
		return err
	}

	return nil
}

func RemoveRoutingPolicyRule(rule *IPRoutingRule) error {
	r := netlink.NewRule()
	r.Table = rule.Table
	r.Src = &net.IPNet{IP: net.ParseIP(rule.Address), Mask: net.CIDRMask(rule.Prefix, 32)}

	if err := netlink.RuleDel(r); err != nil {
		return err
	}

	return nil
}

func ruleExists(rules []netlink.Rule, rule netlink.Rule) bool {
	for i := range rules {
		if ruleEquals(rules[i], rule) {
			return true
		}
	}

	return false
}

func ruleEquals(a, b netlink.Rule) bool {
	return a.Table == b.Table &&
		((a.Src == nil && b.Src == nil) ||
			(a.Src != nil && b.Src != nil && a.Src.String() == b.Src.String())) &&
		((a.Dst == nil && b.Dst == nil) ||
			(a.Dst != nil && b.Dst != nil && a.Dst.String() == b.Dst.String())) &&
		a.OifName == b.OifName &&
		a.IifName == b.IifName

}
