// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package cloud

import (
	"errors"

	"github.com/powersj/whatsthis"
)

type CloudManager struct {
	CloudProvider string
	MetaData      interface{}
}

var CM *CloudManager

func NewCloudManager() (*CloudManager, error) {
	c, err := whatsthis.Cloud()
	if err != nil || len(c.Name) <= 0 {
		return nil, errors.New("unknown cloud enviroment")
	}

	m := &CloudManager{
		CloudProvider: c.Name,
	}

	CM = m
	return m, nil
}

func GetConext() (c *CloudManager) {
	return CM
}
