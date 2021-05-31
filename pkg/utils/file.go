// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
)

func PathExists(path string) bool {
	if err, r := os.Stat(path); err != nil && os.IsNotExist(r) {
		return false
	}

	return true
}

func CreateRunDir(path string) error {
	if err := os.MkdirAll(path, os.ModePerm); err != nil {
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

func CreateAndSaveJSON(path string, content interface{}) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return err
	}
	defer f.Close()

	d, _ := json.MarshalIndent(content, "", " ")
	f.Write(d)

	return nil
}
