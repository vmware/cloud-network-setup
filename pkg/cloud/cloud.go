// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package cloud

import "github.com/powersj/whatsthis"

// CloudManager Conext
type CloudManager struct {
	CloudProvider string
	MetaData      interface{}
}

var CM *CloudManager

// NewCloudManager Constructor
func NewCloudManager() (*CloudManager, error) {
	c, err := whatsthis.Cloud()
	if err != nil {
		return nil, err
	}

	m := &CloudManager{
		CloudProvider: c.Name,
	}

	CM = m
	return m, nil
}

// GetConext vcloud manager
func GetConext() (c *CloudManager) {
	return CM
}
