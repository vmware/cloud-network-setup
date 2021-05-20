// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package conf

import (
	"errors"
	"flag"
	"time"

	"github.com/cloud-network-setup/pkg/utils"
	"github.com/sirupsen/logrus"
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
	flag.StringVar(&LogLevelFlag, "CLOUD_NETWORK_LOG_LEVEL", defaultLogLevel, "Default log level.")
	flag.StringVar(&LogFormatFlag, "CLOUD_NETWORK_LOG_FORMAT", defaultLogFormat, "Default log format.")
	flag.Uint64("refreshtimer", defaultRefreshTimer, "Default metadata refresh timer.")
}

// SetLogLevel: Set log level
func SetLogLevel(level string) error {
	if level == "" {
		return errors.New("Failed to parse log level")
	}

	l, err := logrus.ParseLevel(level)
	if err != nil {
		logrus.WithField("level", level).Warn("Failed to parse log level, fallback to 'info'")
		return errors.New("Invalid log format")
	} else {
		logrus.SetLevel(l)
	}

	return nil
}

// SetLogFormat: Sets log format
func SetLogFormat(format string) error {
	if format == "" {
		return errors.New("Failed to parse log format")
	}

	switch format {
	case "json":
		log.SetFormatter(&logrus.JSONFormatter{
			DisableTimestamp: true,
		})

		break
	case "text":
		log.SetFormatter(&logrus.TextFormatter{
			DisableTimestamp: true,
		})

	default:
		return errors.New("Invalid log format")
	}

	return nil
}

func Parse() (*Config, error) {
	var conf Config

	flag.Parse()

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

	t, err := time.ParseDuration(conf.System.RefreshTimer)
	if err != nil {
		log.Warningf("Failed to parse RefreshTimer=%+v", conf.System.RefreshTimer)
	} else {
		RefreshTimerFlag = t
	}

	viper.AutomaticEnv()

	err = SetLogLevel(viper.GetString("CLOUD_NETWORK_LOG_LEVEL"))
	if err != nil {
		err = SetLogLevel(conf.System.LogLevel)
		if err != nil {
			log.Warningf("Failed to parse LogLevel=%+v", conf.System.LogLevel)
		} else {
			LogLevelFlag = conf.System.LogLevel
		}
	}

	log.Debugf("Log level set to '%+v'", log.GetLevel().String())

	err = SetLogFormat(viper.GetString("CLOUD_NETWORK_LOG_FORMAT"))
	if err != nil {
		err = SetLogFormat(conf.System.LogFormat)
		if err != nil {
			log.Warningf("Failed to parse LogFormat=%+v", conf.System.LogFormat)
		} else {
			LogFormatFlag = conf.System.LogFormat
		}
	}

	log.Debugf("Successfully parsed Address='%+v' and Port='%+v'", conf.Network.Address, conf.Network.Port)

	return &conf, nil
}
