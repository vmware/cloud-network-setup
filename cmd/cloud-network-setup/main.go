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
	"syscall"
	"time"

	"github.com/okzk/sdnotify"
	log "github.com/sirupsen/logrus"

	"github.com/cloud-network-setup/pkg/cloud"
	cloudprovider "github.com/cloud-network-setup/pkg/cloudprovider"
	"github.com/cloud-network-setup/pkg/conf"
	"github.com/cloud-network-setup/pkg/router"
)

func retriveMetaDataAndConfigure(c *cloud.CloudManager) error {
	err := cloudprovider.AcquireCloudMetadata(c)
	if err != nil {
		log.Errorf("Failed to fetch cloud metadata from endpoint")
		return err
	}

	cloudprovider.SaveMetaData(c)
	if err != nil {
		log.Errorf("Failed to save cloud metadata: %s", err)
		return err
	}

	err = cloudprovider.ConfigureNetworkMetadata(c)
	if err != nil {
		log.Errorf("Failed to configure cloud metadata link address: %s", err)
		return err
	}

	return nil
}

func main() {
	log.Infof("cloud-network-setup: v%s (built %s)", conf.Version, runtime.Version())

	c, err := conf.Parse()
	if err != nil {
		log.Errorf("Failed to parse conf file '%+v': %+v", conf.ConfFile, err)
	}

	err = os.MkdirAll("/run/cloud-network-setup/links", os.ModePerm)
	if err != nil {
		log.Errorf("Failed create run dir '/run/cloud-network-setup/links' for Cloud Manager: '%+v'", err)
	}

	m, err := cloud.NewCloudManager()
	if err != nil {
		log.Errorf("Failed initialize Cloud Manager: '%+v'")
		os.Exit(1)
	}

	log.Infof("Detected cloud enviroment: '%+v'", m.CloudProvider)

	err = retriveMetaDataAndConfigure(m)
	if err != nil {
		log.Errorf("Failed to fetch instance metadata and apply to links: %+v ", err)
	}

	// Periodic timer to fetch data from endpoint
	go func() {
		tick := time.Tick(time.Duration(conf.RefreshTimerFlag.Seconds()) * time.Second)
		for {
			<-tick
			err = retriveMetaDataAndConfigure(m)
			if err != nil {
				log.Errorf("Failed to refresh instance metadata from endpoint '%s': %+v ", m.CloudProvider, err)
			}
		}
	}()

	router := router.NewRouter()
	srv := http.Server{
		Addr:    net.JoinHostPort(c.Address, c.Port),
		Handler: router,
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

	log.Infof("Local Instance Metadata Cache Server listening at '%s':'%s'", c.Address, c.Port)
	log.Info(srv.ListenAndServe())
}
