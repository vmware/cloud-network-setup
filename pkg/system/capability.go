// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"github.com/syndtr/gocapability/capability"
)

func SetCapability() error {
	caps, err := capability.NewPid2(0)
	if err != nil {
		return err
	}

	caps.Clear(capability.CAPS)
	caps.Set(capability.CAPS, capability.CAP_SYS_ADMIN|capability.CAP_NET_BIND_SERVICE)
	if err := caps.Apply(capability.CAPS); err != nil {
		return err
	}

	return nil
}
