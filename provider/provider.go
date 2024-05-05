// Copyright 2024 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"errors"
	"sync"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/vmware/cloud-network-setup/pkg/cloud"
	"github.com/vmware/cloud-network-setup/pkg/network"
)

type Environment struct {
	Kind string

	az  *Azure
	gcp *GCP
	ec2 *EC2

	Links                     network.Links
	RouteTable                int
	AddressesByMAC            map[string]map[string]bool
	RoutesByIndex             map[int]*network.Route
	RoutingRulesByAddressFrom map[string]*network.RoutingPolicyRule
	RoutingRulesByAddressTo   map[string]*network.RoutingPolicyRule

	Mutex *sync.Mutex
}

func New(provider string) *Environment {
	m := &Environment{
		Kind:                      provider,
		RouteTable:                network.ROUTE_TABLE_BASE,
		AddressesByMAC:            make(map[string]map[string]bool),
		RoutesByIndex:             make(map[int]*network.Route),
		RoutingRulesByAddressFrom: make(map[string]*network.RoutingPolicyRule),
		RoutingRulesByAddressTo:   make(map[string]*network.RoutingPolicyRule),
		Mutex:                     &sync.Mutex{},
	}

	switch provider {
	case cloud.Azure:
		m.az = NewAzure()
	case cloud.AWS:
		m.ec2 = NewEC2()
	case cloud.GCP:
		m.gcp = NewGCP()
	default:
		return nil
	}

	return m
}

func AcquireCloudMetadata(m *Environment) error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	var err error
	m.Links, err = network.AcquireLinks()
	if err != nil {
		log.Errorf("Failed to acquire link information: %+v", err)
		return nil
	}

	switch m.Kind {
	case cloud.Azure:
		err = m.az.FetchCloudMetadata()
	case cloud.AWS:
		err = m.ec2.FetchCloudMetadata()
	case cloud.GCP:
		err = m.gcp.FetchCloudMetadata()
	default:
		return errors.New("unknown cloud environment")
	}

	if err != nil {
		log.Errorf("Failed to retrieve cloud provider '%+v' instance metadata: %v", m.Kind, err)
		return err
	}

	return nil
}

func ConfigureNetworkMetadata(m *Environment) error {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	switch m.Kind {
	case cloud.Azure:
		return m.az.ConfigureNetworkFromCloudMeta(m)
	case cloud.AWS:
		return m.ec2.ConfigureNetworkFromCloudMeta(m)
	case cloud.GCP:
		return m.gcp.ConfigureNetworkFromCloudMeta(m)
	default:
		return errors.New("unknown cloud environment")
	}
}

func SaveMetaData(m *Environment) error {
	switch m.Kind {
	case cloud.Azure:
		if err := m.az.SaveCloudMetadata(); err != nil {
			return err
		}

		if err := m.az.LinkSaveCloudMetadata(m); err != nil {
			return err
		}
	case cloud.AWS:
		if err := m.ec2.SaveCloudMetadata(); err != nil {
			return err
		}

		if err := m.ec2.SaveCloudMetadataIdentityCredentials(); err != nil {
			return err
		}

		if err := m.ec2.LinkSaveCloudMetadata(m); err != nil {
			return err
		}
	case cloud.GCP:
		if err := m.gcp.SaveCloudMetadata(); err != nil {
			return err
		}

		if err := m.gcp.LinkSaveCloudMetadata(m); err != nil {
			return err
		}
	default:
		return errors.New("unknown cloud environment")
	}

	return nil
}

func RegisterRouterCloud(r *mux.Router, e *Environment) {
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
