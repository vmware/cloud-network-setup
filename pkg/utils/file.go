// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"os"
	"path/filepath"
	"strconv"
)

func PathExists(path string) bool {
	_, r := os.Stat(path)
	if os.IsNotExist(r) {
		return false
	}

	return true
}

func CreateRunDir(path string) error {
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return err
	}

	return nil
}

func CreateStatefile(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}

	defer f.Close()

	return nil
}

func CreateLinkStatefile(path string, index int) error {
	s := strconv.Itoa(index)
	file := filepath.Join("/run/cloud-network-setup/links", s)

	f, err := os.Create(file)
	if err != nil {
		return err
	}

	defer f.Close()

	return nil
}
