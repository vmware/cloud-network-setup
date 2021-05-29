// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"errors"
	"reflect"
	"strings"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/cloud-network-setup/pkg/cloud"
	"github.com/cloud-network-setup/pkg/network"
)

type Enviroment struct {
	Kind string

	az  *Azure
	gcp *GCP
	ec2 *EC2

	routeTable            int
	addressesByMAC        map[string][]string
	routingRulesByAddress map[string]*network.IPRoutingRule
}

func New(provider string) *Enviroment {
	m := &Enviroment{
		Kind:                  provider,
		routeTable:            network.ROUTE_TABLE_BASE,
		addressesByMAC:        make(map[string][]string),
		routingRulesByAddress: make(map[string]*network.IPRoutingRule),
	}

	switch provider {
	case cloud.Azure:
		m.az = NewAzure()
	case cloud.AWS:
		m.ec2 = NewEC2()
	case cloud.GCP:
		m.gcp = NewGCP()
	default:
	}

	return m
}

func AcquireCloudMetadata(m *Enviroment) error {
	var err error

	switch m.Kind {
	case cloud.Azure:
		err = m.az.FetchCloudMetadata()
	case cloud.AWS:
		err = m.ec2.FetchCloudMetadata()
	case cloud.GCP:
		err = m.gcp.FetchCloudMetadata()
	default:
		return errors.New("unknown cloud enviroment")
	}

	if err != nil {
		log.Warningf("Failed to retrieve cloud provider '%+v' instance metadata: %+v", m.Kind, err)
		return err
	}

	return nil
}

func ConfigureNetworkMetadata(m *Enviroment) error {
	switch m.Kind {
	case cloud.Azure:
		return m.az.ConfigureNetworkFromCloudMeta(m)
	case cloud.AWS:
		return m.ec2.ConfigureCloudMetadataNetwork(m)
	case cloud.GCP:
		return m.gcp.ConfigureCloudMetadataAddress()
	default:
		return errors.New("unknown cloud enviroment")
	}
}

func (m *Enviroment) configureNetwork(link *network.Link, newAddresses map[string]bool) error {
	existingAddresses, err := network.GetIPv4Addreses(link.Name)
	if err != nil {
		log.Errorf("Failed to fetch Ip addresses of link='%+v' ifindex='%+v': %+v", link.Name, link.Ifindex, err)
		return err
	}

	if len(m.addressesByMAC[link.Mac]) > 0 {
		earlierAddresses := m.addressesByMAC[link.Mac]

		eq := reflect.DeepEqual(newAddresses, earlierAddresses)
		if eq {
			log.Debugf("Old metadata addresses='%+v' and new addresses='%+v' received from Azure IMDS endpoint are equal. Skipping ...",
				existingAddresses, newAddresses)
			return nil
		}

		// Purge old addresses
		for _, i := range earlierAddresses {
			_, ok := newAddresses[i]
			if !ok {
				err = network.RemoveIPAddress(link.Name, i)
				if err != nil {
					log.Errorf("Failed to remove address='%+v' from link='%+v': '%+v'", i, link.Name, link.Ifindex, err)
					continue
				} else {
					log.Infof("Successfully removed address='%+v on link='%+v' ifindex='%d'", i, link.Name, link.Ifindex)

					r, ok := m.routingRulesByAddress[i]
					if ok {
						m.removeRoutingPolicyRule(r, link)
						delete(m.routingRulesByAddress, i)
					}
				}
			}
		}
	}

	for i := range newAddresses {
		_, ok := existingAddresses[i]
		if !ok {
			err = network.SetAddress(link.Name, i)
			if err != nil {
				log.Errorf("Failed to add address='%+v' to link='%+v' ifindex='%d': +v", i, link.Name, link.Ifindex, err)
				continue
			}

			log.Infof("Successfully added address='%+v on link='%+v' ifindex='%d'", i, link.Name, link.Ifindex)

			// https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-multiple-ip-addresses-portal#add
			// echo 150 custom >> /etc/iproute2/rt_tables
			// ip rule add from 10.0.0.5 lookup custom
			// ip route add default via 10.0.0.1 dev eth2 table custom

			if err := m.configureRoute(link); err != nil {
				continue
			}

			if err := m.configureRoutingPolicyRule(link, i); err != nil {
				continue
			}
		}
	}
	delete(m.addressesByMAC, link.Mac)

	var a []string
	for i := range newAddresses {
		a = append(a, i)
	}
	m.addressesByMAC[link.Mac] = a

	return nil
}

func (m *Enviroment) configureRoute(link *network.Link) error {
	gw, err := network.GetDefaultIpv4GatewayByLink(link.Ifindex)
	if err != nil {
		log.Infof("Failed to find default gateway for the link='%s' ifindex='%d. Looking for any default GW instead': '%+v'", link.Name, link.Ifindex, err)

		gw, err = network.GetDefaultIpv4Gateway()
		if err != nil {
			log.Errorf("Failed to determine default gateway: '%+v'", err)
			return err
		}
	}

	err = network.AddRoute(link.Ifindex, m.routeTable+link.Ifindex, gw)
	if err != nil {
		log.Errorf("Failed to added default gateway='%+v' for link='%+v' ifindex='%+v': '%+v' table='%d': %+v", gw, link.Name, link.Ifindex, m.routeTable+link.Ifindex, err)
	}

	log.Debugf("Successfully added default gateway='%+v' for link='%+v' ifindex='%+v' table='%d'", gw, link.Name, link.Ifindex, m.routeTable+link.Ifindex)

	return nil
}

func (m *Enviroment) configureRoutingPolicyRule(link *network.Link, address string) error {
	s := strings.SplitAfter(address, "/")
	addr := strings.TrimSuffix(s[0], "/")

	rule := &network.IPRoutingRule{
		Address: addr,
		Table:   m.routeTable + link.Ifindex,
	}

	err := network.AddRoutingPolicyRule(rule)
	if err != nil {
		log.Errorf("Failed to add routing policy rule for link='%+v' ifindex='%+v' table='%d': '%+v'", link.Name, link.Ifindex, rule.Table, err)
	}
	m.routingRulesByAddress[address] = rule

	log.Debugf("Successfully added routing policy rule in route table='%d' for link='%+v' ifindex='%+v'", rule.Table, link.Name, link.Ifindex)

	return nil
}

func (m *Enviroment) removeRoutingPolicyRule(rule *network.IPRoutingRule, link *network.Link) error {
	err := network.RemoveRoutingPolicyRule(rule)
	if err != nil {
		log.Errorf("Failed to add routing policy rule for link='%+v' ifindex='%+v' table='%d': '%+v'", link.Name, link.Ifindex, rule.Table, err)
	}

	log.Debugf("Successfully removed routing policy rule for link='%+v' ifindex='%+v' table='%d'", link.Name, link.Ifindex, rule.Table)

	m.routingRulesByAddress[rule.Address] = rule

	return nil
}

func SaveMetaData(m *Enviroment) error {
	switch m.Kind {
	case cloud.Azure:
		if err := m.az.SaveCloudMetadata(); err != nil {
			return err
		}

		if err := m.az.LinkSaveCloudMetadata(); err != nil {
			return err
		}
	case cloud.AWS:
		if err := m.ec2.SaveCloudMetadata(); err != nil {
			return err
		}

		if err := m.ec2.SaveCloudMetadataIdentityCredentials(); err != nil {
			return err
		}

		if err := m.ec2.LinkSaveCloudMetadata(); err != nil {
			return err
		}
	case cloud.GCP:
		if err := m.gcp.SaveCloudMetadata(); err != nil {
			return err
		}

		if err := m.gcp.LinkSaveCloudMetadata(); err != nil {
			return err
		}
	default:
		return errors.New("unknown cloud enviroment")
	}

	return nil
}

func RegisterRouterCloud(r *mux.Router, e *Enviroment) {
	n := r.PathPrefix("/cloud").Subrouter()

	switch e.Kind {
	case cloud.Azure:
		RegisterRouterAzure(n, e)
	case cloud.AWS:
		RegisterRouterEC2(n, e)
	case cloud.GCP:
		RegisterRouterGCP(n, e)
	}
}
