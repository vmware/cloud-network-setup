// Copyright 2024 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"context"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

const (
	defaultRequestTimeout = 5 * time.Second
)

func Dispatch(url string, headers map[string]string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultRequestTimeout)
	defer cancel()

	httpRequest, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		httpRequest.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(httpRequest)
	if err != nil {
		return nil, errors.Wrap(err, "could not complete HTTP request")
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.Wrap(err, "non-200 status code")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
