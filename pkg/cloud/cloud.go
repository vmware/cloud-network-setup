// Copyright 2024 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"io/ioutil"
	"strings"
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

	// ALibaba Cloud Platform cloud provider.
	Alibaba string = "alibaba"

	// Oracle Cloud Platform cloud provider.
	Oracle string = "oracle"

	// Digital Ocean Cloud Platform cloud provider.
	DigitalOcean string = "digital ocean"
)

func DetectCloud() string {
	if DetectAzure() {
		return Azure
	} else if DetectEC2() {
		return AWS
	} else if DetectGCP() {
		return GCP
	} else if DetectAlibaba() {
		return Alibaba
	} else if DetectOracle() {
		return Oracle
	} else if DetectDigitalOcean() {
		return DigitalOcean
	}

	return ""
}

func DetectAzure() bool {
	vendor, _ := ioutil.ReadFile("/sys/class/dmi/id/sys_vendor")
	chassisAssetTag, _ := ioutil.ReadFile("/sys/class/dmi/id/chassis_asset_tag")

	hasVendor := strings.Contains(string(vendor), "Microsoft Corporation")
	hasChassisAssetTag := strings.Contains(string(chassisAssetTag), "7783-7084-3265-9085-8269-3286-77")

	return hasVendor || hasChassisAssetTag
}

func DetectEC2() bool {
	hypervisorUUID, _ := ioutil.ReadFile("/sys/hypervisor/uuid")
	productUUID, _ := ioutil.ReadFile("/sys/class/dmi/id/product_uuid")
	productVersion, _ := ioutil.ReadFile("/sys/class/dmi/id/product_version")

	return strings.HasPrefix(string(hypervisorUUID), "ec2") || strings.HasPrefix(string(productUUID), "ec2") ||
		strings.Contains(string(productVersion), "amazon")
}

func DetectGCP() bool {
	productName, _ := ioutil.ReadFile("/sys/class/dmi/id/product_name")
	return strings.Contains(string(productName), "Google Compute Engine")
}

func DetectAlibaba() bool {
	productName, _ := ioutil.ReadFile("/sys/class/dmi/id/product_name")
	return strings.Contains(string(productName), "Alibaba Cloud")
}

func DetectDigitalOcean() bool {
	vendor, _ := ioutil.ReadFile("/sys/class/dmi/id/sys_vendor")
	return strings.Contains(string(vendor), "DigitalOcean")
}

func DetectOracle() bool {
	chassisAssetTag, _ := ioutil.ReadFile("/sys/class/dmi/id/chassis_asset_tag")
	return strings.Contains(string(chassisAssetTag), "OracleCloud")
}
