// Copyright 2024 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"syscall"

	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"
)

func ApplyCapability(c *syscall.Credential) error {
	caps, err := capability.NewPid2(0)
	if err != nil {
		return err
	}

	caps.Set(capability.CAPS|capability.BOUNDS|capability.AMBIENT, capability.CAP_NET_ADMIN)
	return caps.Apply(capability.CAPS | capability.BOUNDS | capability.AMBIENT)
}

func EnableKeepCapability() error {
	return unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0)
}

func DisableKeepCapability() error {
	return unix.Prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0)
}
