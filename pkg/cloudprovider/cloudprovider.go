// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0
package cloudprovider

import (
	"errors"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/cloud-network-setup/pkg/cloud"
	"github.com/cloud-network-setup/pkg/cloudprovider/azure"
	"github.com/cloud-network-setup/pkg/cloudprovider/ec2"
)

const (
	// None cloud metadata.
	None string = "none"

	// Azure Microsoft Azure cloud provider.
	Azure string = "azure"

	// AWS Amazon Web Services (EC2) cloud provider.
	AWS string = "aws"

	// GCP Google Cloud Platform cloud provider.
	GCP string = "gcp"
)

// AcquireCloudMetadata - Retrive cloud metadata.
func AcquireCloudMetadata(c *cloud.CloudManager) error {
	return fetchCloudMetadata(c)
}

func fetchCloudMetadata(m *cloud.CloudManager) error {
	var err error

	switch m.CloudProvider {
	case Azure:
		err = azure.FetchCloudMetadata(m)
	case AWS:
		err = ec2.FetchCloudMetadata(m)
	default:
		return errors.New("Unknown Cloud Enviroment")
	}

	if err != nil {
		log.Warningf("Failed to retrieve cloud provider '%+v' instance metadata: %+v", m.CloudProvider, err)
		return err
	}

	return nil
}

// ConfigureNetworkMetadata configures network metadata
func ConfigureNetworkMetadata(m *cloud.CloudManager) error {
	switch m.CloudProvider {
	case Azure:
		return azure.ConfigureCloudMetadataAddress(m)
	case AWS:
		return ec2.ConfigureCloudMetadataAddress(m)
	default:
		return errors.New("unknown cloud enviroment")
	}
}

// SaveMetaData Saves cloud metadata ro /run
func SaveMetaData(m *cloud.CloudManager) error {
	var err error

	switch m.CloudProvider {
	case Azure:
		err = azure.SaveCloudMetadata(m)
		if err != nil {
			return err
		}

		err = azure.LinkSaveCloudMetadata(m)
		if err != nil {
			return err
		}
	default:
		return errors.New("unknown cloud enviroment")
	}

	return nil
}

// RegisterRouterCloud regiser with mux
func RegisterRouterCloud(router *mux.Router) {
	n := router.PathPrefix("/cloud").Subrouter()

	switch cloud.GetConext().CloudProvider {
	case Azure:
		azure.RegisterRouterAzure(n)
	case AWS:
		ec2.RegisterRouterEC2(n)
	default:
		return
	}
}
