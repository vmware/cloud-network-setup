// Copyright 2024 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"strconv"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/vmware/cloud-network-setup/pkg/network"
)

const (
	MaxChannelSize = 1024
)

func WatchNetwork(m *Environment) {
	go WatchAddresses(m)
	go WatchLinks(m)
}

func WatchAddresses(m *Environment) {
	updates := make(chan netlink.AddrUpdate)
	done := make(chan struct{}, MaxChannelSize)

	if err := netlink.AddrSubscribeWithOptions(updates, done, netlink.AddrSubscribeOptions{
		ErrorCallback: func(err error) {
			log.Errorf("Received error from address update subscription: %v", err)
		},
	}); err != nil {
		log.Errorf("Failed to subscribe address update: %v", err)
		return
	}

	for {
		select {
		case <-done:
			log.Info("Address watcher failed")
		case updates, ok := <-updates:
			if !ok {
				break
			}

			a := updates.LinkAddress.IP.String()
			mask, _ := updates.LinkAddress.Mask.Size()

			ip := a + "/" + strconv.Itoa(mask)

			log.Infof("Received address update: %v", updates)

			if updates.NewAddr {
				log.Infof("Address='%s' added to link ifindex='%d'", ip, updates.LinkIndex)
			} else {
				log.Infof("Address='%s' removed from link ifindex='%d'", ip, updates.LinkIndex)

				log.Debugf("Dropping configuration link ifindex='%d' address='%s'", updates.LinkIndex, ip)

				m.dropConfiguration(updates.LinkIndex, ip)
			}
		}
	}
}

func WatchLinks(m *Environment) {
	updates := make(chan netlink.LinkUpdate)
	done := make(chan struct{}, MaxChannelSize)

	if err := netlink.LinkSubscribeWithOptions(updates, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) {
			log.Errorf("Received error from link update subscription: %v", err)
		},
	}); err != nil {
		log.Errorf("Failed to subscribe link update: %v", err)
		return
	}

	for {
		select {
		case <-done:
			log.Info("Link watcher failed")
		case updates, ok := <-updates:
			if !ok {
				break
			}

			log.Infof("Received Link update: %v", updates)

			link := network.Link{
				Ifindex:   updates.Link.Attrs().Index,
				Mac:       updates.Link.Attrs().HardwareAddr.String(),
				MTU:       updates.Attrs().MTU,
				OperState: updates.Attrs().OperState.String(),
			}

			m.updateLink(&link)
		}
	}
}

func (m *Environment) updateLink(link *network.Link) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	l, ok := m.Links.LinksByMAC[link.Mac]
	if !ok {
		return
	}

	l.MTU = link.MTU
	l.OperState = link.OperState
}

func (m *Environment) dropConfiguration(ifIndex int, address string) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	mac, err := network.GetLinkMacByIndex(&m.Links, ifIndex)
	if err != nil {
		log.Info("Failed to find Link ifindex='%d': %+v", ifIndex, err)
		return
	}

	_, ok := m.AddressesByMAC[mac]
	if !ok {
		return
	}
	link := m.Links.LinksByMAC[mac]

	log.Debugf("Dropping routing rules link='%s' ifindex='%d' address='%s'", link.Name, link.Ifindex, address)

	m.removeRoutingPolicyRule(address, &link)
	delete(m.AddressesByMAC[mac], address)
}
