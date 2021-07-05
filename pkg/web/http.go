// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"io/ioutil"
	"net/http"
)

func Fetch(url string, headers map[string]string) ([]byte, error) {
	client, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		client.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(client)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
