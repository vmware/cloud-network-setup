// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"encoding/json"
	"os"
	"path"

	"github.com/cloud-network-setup/pkg/conf"
)

func CreateStateDirs(provider string) error {
	if err := os.MkdirAll(conf.LinkStateDir, os.FileMode(0775)); err != nil {
		return err
	}

	kind := path.Join(conf.SystemStateDir, provider)
	if err := os.MkdirAll(kind, os.FileMode(0775)); err != nil {
		return err
	}

	return nil
}

func CreateAndSaveJSON(path string, content interface{}) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	defer f.Close()

	d, _ := json.MarshalIndent(content, "", "  ")
	f.Write(d)

	return nil
}
