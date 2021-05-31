// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package conf

import (
	"errors"
	"flag"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/cloud-network-setup/pkg/parser"
)

const (
	Version  = "0.1"
	ConfPath = "/etc/cloud-network"

	SystemStateDir   = "/run/cloud-network"
	ProviderStateDir = SystemStateDir + "/provider"
	LinkStateDir     = SystemStateDir + "/links"
	SystemState      = SystemStateDir + "/system"
	ConfFile         = "cloud-network"

	DefaultHttpRequestTimeout = 10000
)

// flag
var (
	IPFlag           string
	PortFlag         string
	MultiLink        string
	LogLevelFlag     string
	LogFormatFlag    string
	LogTimeStampFlag bool
	RefreshTimerFlag time.Duration
)

// Config config file key value
type Config struct {
	Network `mapstructure:"Network"`
	System  `mapstructure:"System"`
}

//Network IP Address and Port
type Network struct {
	Address       string
	Port          string
	Supplementary string
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

func SetLogLevel(level string) error {
	if level == "" {
		return errors.New("failed to parse log level")
	}

	l, err := logrus.ParseLevel(level)
	if err != nil {
		logrus.WithField("level", level).Warn("Failed to parse log level, fallback to 'info'")
		return errors.New("Unsupported")
	} else {
		logrus.SetLevel(l)
	}

	return nil
}

func SetLogFormat(format string) error {
	if len(format) <= 0 {
		return errors.New("failed to parse log format")
	}

	switch format {
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{
			DisableTimestamp: true,
		})

	case "text":
		logrus.SetFormatter(&logrus.TextFormatter{
			DisableTimestamp: true,
		})

	default:
		return errors.New("unsupported")
	}

	return nil
}

func Parse() (*Config, error) {
	var conf Config

	viper.SetConfigName(ConfFile)
	viper.AddConfigPath(ConfPath)

	err := viper.ReadInConfig()
	if err != nil {
		logrus.Warningf("Failed to parse config file. Using defaults: '%+v'", err)

		flag.Parse()
		return nil, err
	}

	err = viper.Unmarshal(&conf)
	if err != nil {
		logrus.Warningf("Failed to decode configuration: '%+v'", err)
		return nil, err
	}

	_, err = parser.ParseIP(conf.Network.Address)
	if err != nil {
		logrus.Warningf("Failed to parse Address='%+v' port='%+v': %+v", conf.Network.Address, conf.Network.Port, err)
		IPFlag = conf.Network.Address
	}

	_, err = parser.ParsePort(conf.Network.Port)
	if err != nil {
		logrus.Warningf("Failed to parse Port='%+v': %+v", conf.Network.Port, err)
		PortFlag = conf.Network.Port
	}

	t, err := time.ParseDuration(conf.System.RefreshTimer)
	if err != nil {
		logrus.Warningf("Failed to parse RefreshTimer='%+v': %+v", conf.System.RefreshTimer, err)
	} else {
		RefreshTimerFlag = t
	}

	viper.AutomaticEnv()

	err = SetLogLevel(viper.GetString("CLOUD_NETWORK_LOG_LEVEL"))
	if err != nil {
		err = SetLogLevel(conf.System.LogLevel)
		if err != nil {
			logrus.Warningf("Failed to parse LogLevel='%+v': %+v", conf.System.LogLevel, err)
		} else {
			LogLevelFlag = conf.System.LogLevel
		}
	}

	logrus.Debugf("Log level set to '%+v'", logrus.GetLevel().String())

	err = SetLogFormat(viper.GetString("CLOUD_NETWORK_LOG_FORMAT"))
	if err != nil {
		err = SetLogFormat(conf.System.LogFormat)
		if err != nil {
			logrus.Warningf("Failed to parse LogFormat='%+v': %+v", conf.System.LogFormat, err)
		} else {
			LogFormatFlag = conf.System.LogFormat
		}
	}

	logrus.Debugf("Successfully parsed Address='%+v' and Port='%+v'", conf.Network.Address, conf.Network.Port)

	return &conf, nil
}
