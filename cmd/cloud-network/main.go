// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/okzk/sdnotify"
	log "github.com/sirupsen/logrus"

	"github.com/cloud-network-setup/pkg/cloud"
	"github.com/cloud-network-setup/pkg/conf"
	"github.com/cloud-network-setup/pkg/network"
	"github.com/cloud-network-setup/pkg/provider"
	"github.com/cloud-network-setup/pkg/system"
)

func configureSupplementaryLinks(s string) error {
	words := strings.Fields(s)
	if len(words) <= 0 {
		return nil
	}

	for _, w := range words {
		link, err := net.InterfaceByName(w)
		if err != nil {
			log.Warningf("Failed to find link='%s'. Ignoring ...: %+v", w, err)
			continue
		}

		if err = network.ConfigureByIndex(link.Index); err != nil {
			log.Errorf("Failed to configure network for link='%s' ifindex='%d': %+v", link.Name, link.Index, err)
			return err
		}

		log.Debugf("Successfully configured network for link='%s' ifindex='%d'", link.Name, link.Index)
	}

	return nil
}

func retriveMetaDataAndConfigure(m *provider.Environment) error {
	if err := provider.AcquireCloudMetadata(m); err != nil {
		log.Errorf("Failed to fetch cloud metadata from endpoint: %+v", err)
		return err
	}

	if err := provider.SaveMetaData(m); err != nil {
		log.Errorf("Failed to save cloud metadata: %+v", err)
		return err
	}

	if err := provider.ConfigureNetworkMetadata(m); err != nil {
		log.Errorf("Failed to configure cloud metadata link address: %+v", err)
		return err
	}

	return nil
}

func main() {
	log.Infof("cloud-network-setup: v%+v (built '%+v')", conf.Version, runtime.Version())

	kind := cloud.DetectCloud()
	if len(kind) <= 0 {
		log.Fatal("Failed to detect cloud environment, Aborting ...")
		os.Exit(1)
	}

	log.Infof("Detected cloud environment: '%s'", kind)

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
				log.Warningf("Failed to get 'user cloud-network' credentials: %+v", err)
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

	if err := retriveMetaDataAndConfigure(m); err != nil {
		log.Printf("Failed to: %+v", err)
	}

	configureSupplementaryLinks(c.Network.Supplementary)

	// Periodic timer to fetch data from endpoint
	go func() {
		tick := time.Tick(time.Duration(conf.RefreshTimerFlag.Seconds()) * time.Second)
		for {
			<-tick
			err = retriveMetaDataAndConfigure(m)
			if err != nil {
				log.Errorf("Failed to: %+v", err)
			}
		}
	}()

	r := mux.NewRouter()
	apiRouter := r.PathPrefix("/api").Subrouter()
	provider.RegisterRouterCloud(apiRouter, m)

	srv := http.Server{
		Addr:    net.JoinHostPort(c.Address, c.Port),
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

	log.Infof("Local Instance Metadata Cache Server listening at '%+v':'%+v'", c.Address, c.Port)
	log.Info(srv.ListenAndServe())
}
