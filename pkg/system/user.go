// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"os/user"
	"strconv"
	"syscall"
)

func GetUserCredentials(u string) (int, int, *user.User, error) {
	user, err := user.Lookup(u)
	if err != nil {
		return -1, -1, nil, err
	}

	uid, _ := strconv.Atoi(user.Uid)
	gid, _ := strconv.Atoi(user.Gid)

	return uid, gid, user, nil
}

func SwitchUser(u *user.User) (err error) {
	var uid, gid int

	if gid, err = strconv.Atoi(u.Gid); err != nil {
		return
	}
	if uid, err = strconv.Atoi(u.Uid); err != nil {
		return
	}

	if err = syscall.Setresgid(gid, gid, gid); err != nil {
		return err
	}
	if err = syscall.Setresuid(uid, uid, uid); err != nil {
		return err
	}

	return nil
}
