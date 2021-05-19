// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"errors"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

var LogLevelSet bool
var LogFormatSet bool

// SetLogLevel: Set log level
func SetLogLevel(level string) error {
	if level == "" {
		return nil
	}

	l, err := logrus.ParseLevel(level)
	if err != nil {
		logrus.WithField("level", level).Warn("Failed to parse log level, fallback to 'info'")
		return errors.New("Invalid log format")
	} else {
		logrus.SetLevel(l)
		LogLevelSet = true
	}

	return nil
}

// SetLogFormat: Sets log format
func SetLogFormat(format string) error {
	switch format {
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{
			DisableTimestamp: true,
		})

		LogFormatSet = true
		break
	case "text":
		logrus.SetFormatter(&logrus.TextFormatter{
			DisableTimestamp: true,
		})

		LogFormatSet = true
	default:
		return errors.New("Invalid log format")
	}

	return nil
}

// InitLog initialize the logger
func InitLog() error {
	viper.AutomaticEnv()

	SetLogLevel(viper.GetString("log.level"))
	SetLogFormat(viper.GetString("log.format"))

	return nil
}
