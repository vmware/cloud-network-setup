// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package conf

import (
	"errors"
	"time"

	"github.com/cloud-network-setup/pkg/parser"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	Version = "0.1"

	ConfFile = "cloud-network"
	ConfPath = "/etc/cloud-network"

	SystemStateDir   = "/run/cloud-network"
	SystemState      = SystemStateDir + "/system"
	LinkStateDir     = SystemStateDir + "/links"
	ProviderStateDir = SystemStateDir + "/provider"

	DefaultHttpRequestTimeout = 10000
)

const (
	DefaultAddress      = "127.0.0.1"
	DefaultPort         = "5209"
	DefaultLogLevel     = "info"
	DefaultLogFormat    = "text"
	DefaultRefreshTimer = "300s"
)

// Config config file key value
type Config struct {
	Network `mapstructure:"Network"`
	System  `mapstructure:"System"`
}

// Network IP Address and Port
type Network struct {
	Address string
	Port    string

	Supplementary string
	PrimaryAddress bool
}

type System struct {
	LogLevel     string
	LogFormat    string
	RefreshTimer string
}

func SetLogLevel(level string) error {
	if level == "" {
		return errors.New("unsupported")
	}

	l, err := logrus.ParseLevel(level)
	if err != nil {
		logrus.Warn("Failed to parse log level, falling back to 'info'")
		return errors.New("unsupported")
	} else {
		logrus.SetLevel(l)
	}

	return nil
}

func SetLogFormat(format string) error {
	if format == "" {
		return errors.New("unsupported")
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
		logrus.Warn("Failed to parse log format, falling back to 'text'")
		return errors.New("unsupported")
	}

	return nil
}

func Parse() (*Config, error) {
	viper.SetConfigName(ConfFile)
	viper.AddConfigPath(ConfPath)

	c := Config{}
	if err := viper.ReadInConfig(); err != nil {
		logrus.Warning(err)
	}

	viper.SetDefault("Network.Address", DefaultAddress)
	viper.SetDefault("Network.Port", DefaultPort)
	viper.SetDefault("System.LogFormat", DefaultLogLevel)
	viper.SetDefault("System.LogLevel", DefaultLogFormat)
	viper.SetDefault("System.RefreshTimer", DefaultRefreshTimer)

	if err := viper.Unmarshal(&c); err != nil {
		logrus.Warning(err)
		return nil, err
	}

	if _, err := parser.ParseIP(c.Network.Address); err != nil {
		logrus.Warning(err)
		c.Network.Address = DefaultAddress
	}

	if _, err := parser.ParsePort(c.Network.Port); err != nil {
		logrus.Warning(err)
		c.Network.Port = DefaultPort
	}

	if _, err := time.ParseDuration(c.System.RefreshTimer); err != nil {
		logrus.Warning(err)
		c.System.RefreshTimer = DefaultRefreshTimer
	}

	if err := SetLogLevel(viper.GetString("CLOUD_NETWORK_LOG_LEVEL")); err != nil {
		if err := SetLogLevel(c.System.LogLevel); err != nil {
			c.System.LogLevel = DefaultLogLevel
		}
	}

	logrus.Debugf("Log level set to '%+v'", logrus.GetLevel().String())

	if err := SetLogFormat(viper.GetString("CLOUD_NETWORK_LOG_FORMAT")); err != nil {
		if err = SetLogFormat(c.System.LogFormat); err != nil {
			c.System.LogLevel = DefaultLogFormat
		}
	}

	logrus.Debugf("Successfully parsed Address='%+v' and Port='%+v'", c.Network.Address, c.Network.Port)

	return &c, nil
}
