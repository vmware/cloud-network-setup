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

	"github.com/cloud-network-setup/pkg/cloud"
	cloudprovider "github.com/cloud-network-setup/pkg/cloudprovider"
	"github.com/cloud-network-setup/pkg/conf"
	"github.com/cloud-network-setup/pkg/router"
	"github.com/cloud-network-setup/pkg/utils"
	"github.com/okzk/sdnotify"
	log "github.com/sirupsen/logrus"
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

	utils.InitLog()

	err := conf.ParseConfiguration()
	if err != nil {
		log.Errorf("Failed to parse conf file '%+v': %+v", conf.ConfFile, err)
	}

	os.MkdirAll("/run/cloud-network-setup/links", os.ModePerm)

	c, err := cloud.NewCloudManager()
	if err != nil {
		log.Errorf("Failed initialize Cloud Manager: '%+v'")
		os.Exit(1)
	}

	err = retriveMetaDataAndConfigure(c)
	if err != nil {
		log.Errorf("Failed to fetch metadata and apply to links: %+v ", err)
	}

	//Periodic timer to fetch data from endpoint
	go func() {
		tick := time.Tick(conf.RefreshTimerFlag * time.Second)
		for {
			<-tick
			err = retriveMetaDataAndConfigure(c)
			if err != nil {
				log.Errorf("Failed to refresh metadata from endpoint '%s': %+v ", c.CloudProvider, err)
			}
		}
	}()

	router := router.NewRouter()
	srv := http.Server{
		Addr:    net.JoinHostPort(conf.IPFlag, conf.PortFlag),
		Handler: router,
	}

	s := make(chan os.Signal, 1)
	signal.Notify(s, os.Interrupt)
	signal.Notify(s, syscall.SIGTERM)
	signal.Notify(s, syscall.SIGKILL)
	go func() {
		<-s
		sdnotify.Stopping()
		if err := srv.Shutdown(context.Background()); err != nil {
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

	log.Infof("Local Cache Server listening at %s:%s", conf.IPFlag, conf.PortFlag)
	log.Info(srv.ListenAndServe())
}
