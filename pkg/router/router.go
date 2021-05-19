// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"github.com/cloud-network-setup/pkg/cloudprovider"
	"github.com/gorilla/mux"
)

func NewRouter() *mux.Router {
	r := mux.NewRouter()
	s := r.PathPrefix("/api").Subrouter()

	cloudprovider.RegisterRouterCloud(s)
	return r
}
