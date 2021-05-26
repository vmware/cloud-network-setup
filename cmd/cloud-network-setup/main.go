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
	"github.com/cloud-network-setup/pkg/network"
	"github.com/cloud-network-setup/pkg/router"
	"github.com/cloud-network-setup/pkg/utils"
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

func createStateDirsAndFiles(provider string) error {
	err := os.MkdirAll("/run/cloud-network-setup/links", os.ModePerm)
	if err != nil {
		log.Errorf("Failed create run dir '/run/cloud-network-setup/links': '%+v'", err)
	}

	err = utils.CreateStatefile("/run/cloud-network-setup/system")
	if err != nil {
		log.Errorf("Failed create state file '/run/cloud-network-setup/system': '%+v'", err)
	}

	links, err := network.AcquireLinks()
	if err != nil {
		return err
	}

	for _, l := range links.LinksByMAC {
		err = utils.CreateLinkStatefile("/run/cloud-network-setup/links", l.Ifindex)
		if err != nil {
			log.Errorf("Failed to create state file for link='%+v' index='%+v'", l.Name, l.Ifindex)
			return err
		}
	}

	switch provider {
	case cloudprovider.AWS:
		err := os.MkdirAll("/run/cloud-network-setup/provider/ec2", os.ModePerm)
		if err != nil {
			log.Errorf("Failed create run dir '/run/cloud-network-setup/ec2': '%+v'", err)
			return err
		}
	default:
	}

	return nil
}

func main() {
	log.Infof("cloud-network-setup: v%+v (built '%+v')", conf.Version, runtime.Version())

	c, err := conf.Parse()
	if err != nil {
		log.Errorf("Failed to parse conf file '%+v': %+v", conf.ConfFile, err)
	}

	m, err := cloud.NewCloudManager()
	if err != nil {
		log.Errorf("Failed initialize Cloud Manager: '%+v'", err)
		os.Exit(1)
	}

	createStateDirsAndFiles(m.CloudProvider)

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
				log.Errorf("Failed to refresh instance metadata from endpoint '%v': %+v ", m.CloudProvider, err)
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

	log.Infof("Local Instance Metadata Cache Server listening at '%+v':'%+v'", c.Address, c.Port)
	log.Info(srv.ListenAndServe())
}
