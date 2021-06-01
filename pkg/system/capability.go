// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"fmt"
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
	if e := caps.Apply(capability.CAPS | capability.BOUNDS | capability.AMBIENT); e != nil {
		err = fmt.Errorf("failed to apply capabilities: %w", e)
		return err
	}

	return nil
}

func EnableKeepCapability() error {
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 1, 0, 0, 0); err != nil {
		return err
	}

	return nil
}

func DisableKeepCapability() error {
	if err := unix.Prctl(unix.PR_SET_KEEPCAPS, 0, 0, 0, 0); err != nil {
		return err
	}

	return nil
}
