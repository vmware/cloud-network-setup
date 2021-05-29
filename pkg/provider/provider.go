// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"errors"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/cloud-network-setup/pkg/cloud"
)

type Enviroment struct {
	Kind string
	az   *Azure
	gcp  *GCP
	ec2  *EC2
}

func New(provider string) *Enviroment {
	m := &Enviroment{
		Kind: provider,
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
		return m.az.ConfigureNetworkFromCloudMeta()
	case cloud.AWS:
		return m.ec2.ConfigureCloudMetadataAddress()
	case cloud.GCP:
		return m.gcp.ConfigureCloudMetadataAddress()
	default:
		return errors.New("unknown cloud enviroment")
	}
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
