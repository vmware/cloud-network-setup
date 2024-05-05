// Copyright 2024 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/okzk/sdnotify"
	log "github.com/sirupsen/logrus"

	"github.com/vmware/cloud-network-setup/conf"
	"github.com/vmware/cloud-network-setup/pkg/cloud"
	"github.com/vmware/cloud-network-setup/pkg/network"
	"github.com/vmware/cloud-network-setup/pkg/parser"
	"github.com/vmware/cloud-network-setup/pkg/system"
	"github.com/vmware/cloud-network-setup/provider"
)

func cloudNetworkBegin(m *provider.Environment) error {
	log.Debugf("Connecting to metadata server (%s) ...", m.Kind)

	if err := provider.AcquireCloudMetadata(m); err != nil {
		return err
	}

	log.Debugf("Configuring network from (%s) metadata", m.Kind)

	if err := provider.ConfigureNetworkMetadata(m); err != nil {
		return err
	}

	log.Debugf("Saving (%s) metadata", m.Kind)

	if err := provider.SaveMetaData(m); err != nil {
		return err
	}

	return nil
}

func main() {
	log.Infof("cloud-network: v%+v (built '%+v')", conf.Version, runtime.Version())

	kind := cloud.DetectCloud()
	if len(kind) <= 0 {
		log.Fatal("Failed to detect cloud environment, Aborting ...")
		os.Exit(1)
	}

	log.Infof("Detected cloud environment (%s)", kind)

	c, err := conf.Parse()
	if err != nil {
		log.Errorf("Failed to parse conf file '%s': %+v", conf.ConfFile, err)
	}

	m := provider.New(kind)
	if m == nil {
		log.Errorf("Failed initialize cloud provider. Aborting ...")
		os.Exit(1)
	}

	cred, err := system.GetUserCredentials("")
	if err != nil {
		log.Warningf("Failed to get current user credentials: %+v", err)
	} else {
		if cred.Uid == 0 {
			u, err := system.GetUserCredentials("cloud-network")
			if err != nil {
				log.Warningf("Failed to get user 'cloud-network' credentials: %+v", err)
			} else {
				if err := system.CreateStateDirs(kind, int(u.Uid), int(u.Gid)); err != nil {
					log.Println(err)
				}

				if err := system.EnableKeepCapability(); err != nil {
					log.Warningf("Failed to enable keep capabilities: %+v", err)
				}

				if err := system.SwitchUser(u); err != nil {
					log.Warningf("Failed to switch user: %+v", err)
				}

				if err := system.DisableKeepCapability(); err != nil {
					log.Warningf("Failed to disable keep capabilities: %+v", err)
				}

				err := system.ApplyCapability(u)
				if err != nil {
					log.Warningf("Failed to apply capabilities: +%v", err)
				}
			}
		}
	}

	// Watch network events
	provider.WatchNetwork(m)

	err = cloudNetworkBegin(m)
	if err != nil {
		log.WithError(err)
	} else {
		network.ConfigureSupplementaryLinks(c.Network.Supplementary)
	}

	// Periodic timer to fetch data from endpoint
	t, _ := time.ParseDuration(c.System.RefreshTimer)
	go func() {
		tick := time.Tick(time.Duration(t.Seconds()) * time.Second)
		for {
			<-tick
			err = cloudNetworkBegin(m)
			if err != nil {
				log.WithError(err)
			}
		}
	}()

	r := mux.NewRouter()
	apiRouter := r.PathPrefix("/api").Subrouter()
	provider.RegisterRouterCloud(apiRouter, m)

	ip, port, _ := parser.ParseIpPort(c.Network.Listen)

	srv := http.Server{
		Addr:    net.JoinHostPort(ip, port),
		Handler: r,
	}

	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt)
	signal.Notify(s, syscall.SIGTERM)
	go func() {
		<-s
		sdnotify.Stopping()
		if err := srv.Shutdown(context.Background()); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}()

	sdnotify.Ready()
	go func() {
		tick := time.Tick(30 * time.Second)
		for {
			<-tick
			sdnotify.Watchdog()
		}
	}()

	log.Infof("Local instance metadata cache Server listening at '%+v':'%+v'", ip, port)
	log.Info(srv.ListenAndServe())
}
