// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package conf

import (
	"flag"
	"time"

	"github.com/cloud-network-setup/pkg/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// App Version
const (
	Version  = "0.1"
	ConfPath = "/etc/cloud-network-setup"
	ConfFile = "cloud-network"
)

// flag
var (
	IPFlag           string
	PortFlag         string
	LogLevelFlag     string
	LogFormatFlag    string
	RefreshTimerFlag time.Duration
)

//Config config file key value
type Config struct {
	Network `mapstructure:"Network"`
	System  `mapstructure:"System"`
}

//Network IP Address and Port
type Network struct {
	Address string
	Port    string
}

type System struct {
	LogLevel     string
	LogFormat    string
	RefreshTimer string
}

func init() {
	const (
		defaultIP           = "127.0.0.1"
		defaultPort         = "5209"
		defaultLogLevel     = "info"
		defaultLogFormat    = "text"
		defaultRefreshTimer = 300
	)

	flag.StringVar(&IPFlag, "ip", defaultIP, "Default Server IP address.")
	flag.StringVar(&PortFlag, "port", defaultPort, "Default Server port.")
	flag.StringVar(&LogLevelFlag, "log.level", defaultLogLevel, "Default log level.")
	flag.StringVar(&LogFormatFlag, "log.format", defaultLogFormat, "Default log format.")
	flag.Uint64("refreshtimer", defaultRefreshTimer, "Default metadata refresh timer.")
}

func loadConfFile() (*Config, error) {
	var conf Config

	viper.SetConfigName(ConfFile)
	viper.AddConfigPath(ConfPath)

	err := viper.ReadInConfig()
	if err != nil {
		log.Warningf("Faild to parse config file, %+v", err)
		return nil, err
	}

	err = viper.Unmarshal(&conf)
	if err != nil {
		log.Warningf("Failed to decode configuration, %+v", err)
		return nil, err
	}

	_, err = utils.ParseIP(conf.Network.Address)
	if err != nil {
		log.Warningf("Failed to parse Address=%+v, %+v", conf.Network.Address, conf.Network.Port)
		IPFlag = conf.Network.Address
	}

	_, err = utils.ParsePort(conf.Network.Port)
	if err != nil {
		log.Warningf("Failed to parse Port=%+v", conf.Network.Port)
		PortFlag = conf.Network.Port
	}

	d, err := time.ParseDuration(conf.System.RefreshTimer)
	if err != nil {
		log.Warningf("Failed to parse RefreshTimer=%+v", conf.System.RefreshTimer)
		return nil, err
	} else {
		RefreshTimerFlag = d
	}

	if !utils.LogLevelSet {
		err = utils.SetLogLevel(conf.System.LogLevel)
		if err != nil {
			log.Warningf("Failed to parse LogLevel=%+v", conf.System.LogLevel)
		} else {
			LogLevelFlag = conf.System.LogLevel
		}
	}

	if !utils.LogFormatSet {
		err = utils.SetLogFormat(conf.System.LogFormat)
		if err != nil {
			log.Warningf("Failed to parse LogFormat=%+v", conf.System.LogFormat)
		} else {
			LogFormatFlag = conf.System.LogFormat
		}
	}

	log.Debugf("Successfully parsed Address=%+v and Port=%+v", conf.Network.Address, conf.Network.Port)

	return &conf, nil
}

// InitConfiguration Init the config from conf file
func ParseConfiguration() error {
	_, err := loadConfFile()
	if err != nil {
		flag.Parse()
		return err
	}

	return nil
}
