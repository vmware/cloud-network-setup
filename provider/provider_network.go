// Copyright 2024 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/vmware/cloud-network-setup/pkg/cloud"
	"github.com/vmware/cloud-network-setup/pkg/network"
)

func (m *Environment) configureNetwork(link *network.Link, newAddresses map[string]bool) error {
	if len(m.AddressesByMAC[link.Mac]) > 0 {
		earlierAddresses := m.AddressesByMAC[link.Mac]

		eq := reflect.DeepEqual(newAddresses, earlierAddresses)
		if eq {
			log.Debugf("Old metadata addresses='%s' and new addresses='%s' received from endpoint are equal. Skipping ...",
				earlierAddresses, newAddresses)
			return nil
		}

		// Purge old addresses
		for i := range earlierAddresses {
			ok := newAddresses[i]
			if !ok {
				if err := network.AddressRemove(link.Name, i); err != nil {
					log.Errorf("Failed to remove address='%s' from link='%s': '%+v'", i, link.Name, link.Ifindex, err)
				} else {
					log.Infof("Successfully removed address='%s on link='%s' ifindex='%d'", i, link.Name, link.Ifindex)
				}

				m.removeRoutingPolicyRule(i, link)
			}
		}
	}

	for i := range newAddresses {
		if link.OperState == "down" {
			if err := network.LinkSetOperStateUp(link.Ifindex); err != nil {
				log.Errorf("Failed to bring up the link='%s' ifindex='%d': %+v", link.Name, link.Ifindex, err)
				return err
			}

			log.Debugf("Successfully brought up the link='%s' ifindex='%d'", link.Name, link.Ifindex)
		}

		var mtu int
		switch m.Kind {
		case cloud.GCP:
			mtu, err := m.gcp.ParseLinkMTUFromMetadataByMac(link.Mac)
			if err != nil || mtu == 0 {
				log.Warningf("Failed to parse MTU link='%s' ifindex='%d': %+v", err)
			}
		}

		if mtu != 0 && link.MTU != mtu {
			if err := network.LinkSetMtu(link.Ifindex, mtu); err != nil {
				log.Warningf("Failed to set MTU link='%s' ifindex='%d': %+v", err)
			} else {
				log.Infof("Successfully MTU set to '%d' link='%s' ifindex='%d'", mtu, link.Name, link.Ifindex)
			}
		}

		if err := network.AddressSet(link.Name, i); err != nil {
			log.Errorf("Failed to add address='%s' to link='%s' ifindex='%d': %+v", i, link.Name, link.Ifindex, err)
			continue
		}

		log.Infof("Successfully added address='%s on link='%s' ifindex='%d'", i, link.Name, link.Ifindex)

		// https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-multiple-ip-addresses-portal#add
		// echo 150 custom >> /etc/iproute2/rt_tables
		// ip rule add from 10.0.0.5 lookup custom
		// ip route add default via 10.0.0.1 dev eth2 table custom

		// https://aws.amazon.com/premiumsupport/knowledge-center/ec2-ubuntu-secondary-network-interface/
		// Gateway configuration
		// #ip route add default via 172.31.16.1 dev eth1 table 1000

		// Routes and rules
		// ip route add 172.31.21.115 dev eth1 table 1000
		// ip rule add from 172.31.21.115 lookup 1000

		// https://cloud.google.com/vpc/docs/create-use-multiple-interfaces
		// sudo ifconfig eth1 192.168.0.2 netmask 255.255.255.255 broadcast 192.168.0.2 mtu 1430
		// echo "1 rt1" | sudo tee -a /etc/iproute2/rt_tables
		// sudo ip route add 192.168.0.1 src 192.168.0.2 dev eth1 table rt1
		// sudo ip route add default via 192.168.0.1 dev eth1 table rt1
		// sudo ip rule add from 192.168.0.2/32 table rt1
		// sudo ip rule add to 192.168.0.2/32 table rt1

		if err := m.configureRoute(link); err != nil {
			continue
		}

		if err := m.configureRoutingPolicyRule(link, i); err != nil {
			continue
		}
	}
	delete(m.AddressesByMAC, link.Mac)
	m.AddressesByMAC[link.Mac] = newAddresses

	return nil
}

func (m *Environment) configureRoute(link *network.Link) error {
	var gw string
	if m.Kind == "gcp" {
		gw, _ = m.gcp.ParseIpv4GatewayFromMetadataByMac(link.Mac)
	}

	var err error
	if len(gw) <= 0 {
		gw, err = network.GetIpv4Gateway(link.Ifindex)
		if err != nil {
			log.Infof("Failed to find gateway for the link='%s' ifindex='%d: %+v", link.Name, link.Ifindex, err)
			return err
		}
	}

	rt := network.Route{
		IfIndex: link.Ifindex,
		Gw:      gw,
		Table:   m.RouteTable + link.Ifindex,
	}

	if err := network.RouteAdd(&rt); err != nil {
		log.Errorf("Failed to add default gateway='%s' for link='%+d' ifindex='%d' table='%d': %+v", gw, link.Name, link.Ifindex, m.RouteTable+link.Ifindex, err)
		return err
	}

	m.RoutesByIndex[link.Ifindex] = &rt

	log.Infof("Successfully added default gateway='%s' for link='%s' ifindex='%+v' table='%d'", gw, link.Name, link.Ifindex, m.RouteTable+link.Ifindex)
	log.Infof("Link='%s' ifindex='%d' is now configured", link.Name, link.Ifindex)

	return nil
}

func (m *Environment) configureRoutingPolicyRule(link *network.Link, address string) error {
	s := strings.SplitAfter(address, "/")
	addr := strings.TrimSuffix(s[0], "/")

	from := &network.RoutingPolicyRule{
		From:  addr,
		Table: m.RouteTable + link.Ifindex,
	}

	err := network.RoutingPolicyRuleAdd(from)
	if err != nil {
		log.Errorf("Failed to add routing policy rule 'from' for link='%s' ifindex='%d' table='%d': %+v", link.Name, link.Ifindex, from.Table, err)
		return err
	} else {
		log.Infof("Successfully added routing policy rule 'from' in route table='%d' for link='%s' ifindex='%+v'", from.Table, link.Name, link.Ifindex)
	}
	m.RoutingRulesByAddressFrom[address] = from

	to := &network.RoutingPolicyRule{
		To:    addr,
		Table: m.RouteTable + link.Ifindex,
	}

	err = network.RoutingPolicyRuleAdd(to)
	if err != nil {
		log.Errorf("Failed to add routing policy rule 'to' for link='%s' ifindex='%d' table='%d': '%+v'", link.Name, link.Ifindex, to.Table, err)
		return err
	} else {
		log.Infof("Successfully added routing policy rule 'to' in route table='%d' for link='%s' ifindex='%+v'", to.Table, link.Name, link.Ifindex)
	}
	m.RoutingRulesByAddressFrom[address] = from

	return nil
}

func (m *Environment) isRulesByTableEmpty(table int) bool {
	from := 0
	to := 0

	for _, v := range m.RoutingRulesByAddressFrom {
		if v.Table == table {
			from++
		}
	}

	for _, v := range m.RoutingRulesByAddressTo {
		if v.Table == table {
			to++
		}
	}

	if from == 0 && to == 0 {
		return true
	}

	return false
}

func (m *Environment) removeRoutingPolicyRule(address string, link *network.Link) error {
	log.Debugf("Removing routing policy rules for address='%s' link='%s'", address, link.Name)

	rule, ok := m.RoutingRulesByAddressFrom[address]
	if ok {
		err := network.RoutingPolicyRuleRemove(rule)
		if err != nil {
			log.Errorf("Failed to add routing policy rule for link='%s' ifindex='%d' table='%d': '%+v'", link.Name, link.Ifindex, rule.Table, err)
		} else {
			log.Debugf("Successfully removed routing policy rule for link='%s' ifindex='%d' table='%d'", link.Name, link.Ifindex, rule.Table)
		}
		delete(m.RoutingRulesByAddressFrom, address)
	}

	rule, ok = m.RoutingRulesByAddressTo[address]
	if ok {
		err := network.RoutingPolicyRuleRemove(rule)
		if err != nil {
			log.Errorf("Failed to add routing policy rule for link='%s' ifindex='%d' table='%d': '%+v'", link.Name, link.Ifindex, rule.Table, err)
		}
		delete(m.RoutingRulesByAddressTo, address)

		log.Debugf("Successfully removed routing policy rule for link='%s' ifindex='%d' table='%d'", link.Name, link.Ifindex, rule.Table)
	}

	rt, ok := m.RoutesByIndex[link.Ifindex]
	if ok {

		if m.isRulesByTableEmpty(rt.Table) {
			log.Debugf("Dropping GW='%s' link='%s' ifindex='%d'  Table='%d'", rt.Gw, link.Name, link.Ifindex, rt.Table)

			network.RouteRemove(rt)
			delete(m.RoutesByIndex, link.Ifindex)
		}
	}

	return nil
}
