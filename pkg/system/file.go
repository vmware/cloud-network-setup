// Copyright 2024 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"encoding/json"
	"os"
	"path"
	"syscall"

	"github.com/vmware/cloud-network-setup/conf"
)

func CreateStateDirs(provider string, uid int, gid int) error {
	if err := os.MkdirAll(conf.LinkStateDir, os.FileMode(07777)); err != nil {
		return err
	}

	if err := syscall.Chown(conf.LinkStateDir, uid, gid); err != nil {
		return err
	}

	if err := syscall.Chown(conf.SystemStateDir, uid, gid); err != nil {
		return err
	}

	kind := path.Join(conf.SystemStateDir, provider)
	if err := os.MkdirAll(kind, os.FileMode(07777)); err != nil {
		return err
	}

	return syscall.Chown(kind, uid, gid)
}

func CreateAndSaveJSON(path string, content interface{}) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, os.FileMode(0755))
	if err != nil {
		return err
	}
	defer f.Close()

	d, _ := json.MarshalIndent(content, "", "  ")
	f.Write(d)

	return nil
}
