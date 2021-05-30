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
	"github.com/cloud-network-setup/pkg/utils"
)

func createStateDirsAndFiles(provider string) error {
	err := os.MkdirAll("/run/cloud-network-setup/links", os.ModePerm)
	if err != nil {
		return err
	}

	err = utils.CreateStatefile("/run/cloud-network-setup/system")
	if err != nil {
		return err
	}

	links, err := network.AcquireLinks()
	if err != nil {
		return err
	}

	for _, l := range links.LinksByMAC {
		err = utils.CreateLinkStatefile("/run/cloud-network-setup/links", l.Ifindex)
		if err != nil {
			return err
		}
	}

	switch provider {
	case cloud.AWS:
		err := os.MkdirAll("/run/cloud-network-setup/provider/ec2", os.ModePerm)
		if err != nil {
			return err
		}
	default:
	}

	return nil
}

func configureSupplementaryLinks(s string) error {
	words := strings.Fields(s)
	if len(words) <= 0 {
		return nil
	}

	for _, w := range words {
		link, err := net.InterfaceByName(w)
		if err != nil {
			return err
		}

		err = network.ConfigureByIndex(link.Index)
		if err != nil {
			log.Errorf("Failed to configure network for link='%s' ifindex='%d': %+v", link.Name, link.Index, err)
			return err
		} else {
			log.Debugf("Successfully configured network for link='%s' ifindex='%d'", link.Name, link.Index)
		}
	}

	return nil
}

func retriveMetaDataAndConfigure(m *provider.Environment) error {
	err := provider.AcquireCloudMetadata(m)
	if err != nil {
		log.Errorf("Failed to fetch cloud metadata from endpoint")
		return err
	}

	provider.SaveMetaData(m)
	if err != nil {
		log.Errorf("Failed to save cloud metadata: %s", err)
		return err
	}

	err = provider.ConfigureNetworkMetadata(m)
	if err != nil {
		log.Errorf("Failed to configure cloud metadata link address: %s", err)
		return err
	}

	return nil
}

func main() {
	log.Infof("cloud-network-setup: v%+v (built '%+v')", conf.Version, runtime.Version())

	cloud := cloud.DetectCloud()
	if len(cloud) <= 0 {
		log.Fatal("Failed to detect cloud environment, Aborting ...")
		os.Exit(1)
	}

	log.Infof("Detected cloud environment: '%+v'", cloud)

	c, err := conf.Parse()
	if err != nil {
		log.Errorf("Failed to parse conf file '%+v': %+v", conf.ConfFile, err)
	}

	m := provider.New(cloud)
	if err != nil {
		log.Errorf("Failed initialize cloud provider: '%+v'", err)
		os.Exit(1)
	}

	err = createStateDirsAndFiles(cloud)
	if err != nil {
		log.Warningf("Failed to create run directories or state files")
	}

	err = retriveMetaDataAndConfigure(m)
	if err != nil {
		log.Errorf("Failed to fetch instance metadata and apply to links: %+v ", err)
	}

	configureSupplementaryLinks(c.Network.Supplementary)

	// Periodic timer to fetch data from endpoint
	go func() {
		tick := time.Tick(time.Duration(conf.RefreshTimerFlag.Seconds()) * time.Second)
		for {
			<-tick
			err = retriveMetaDataAndConfigure(m)
			if err != nil {
				log.Errorf("Failed to refresh instance metadata from endpoint '%v': %+v ", m.Kind, err)
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
