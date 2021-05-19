// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"os"
)

// PathExists - Verify file or dir exists
func PathExists(path string) bool {
	_, r := os.Stat(path)
	if os.IsNotExist(r) {
		return false
	}

	return true
}

// CreateRunDir Creates link labels
func CreateRunDir(path string) error {
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		return err
	}

	return nil
}
