// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package ec2

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/cloud-network-setup/pkg/cloud"
	"github.com/cloud-network-setup/pkg/network"
	"github.com/cloud-network-setup/pkg/utils"
)

const (
	// EC2 Metadata endpoint.
	EC2Endpoint string = "169.254.169.254"

	//EC2 Metadata URL Base URL base
	EC2MetaDataURLBase string = "/latest/meta-data/"

	//EC2 Metadata mac URL URL base
	EC2MetaDataNetwork string = "network/interfaces/macs/"
)

type Mac struct {
	DeviceNumber     string `json:"device-number"`
	InterfaceID      string `json:"interface-id"`
	Ipv4Associations struct {
		Ipv4Association []string
	} `json:"ipv4-associations"`

	LocalHostname       string `json:"local-hostname"`
	LocalIpv4S          string `json:"local-ipv4s"`
	Mac                 string `json:"mac"`
	OwnerID             string `json:"owner-id"`
	PublicHostname      string `json:"public-hostname"`
	PublicIpv4S         string `json:"public-ipv4s"`
	SecurityGroupIds    string `json:"security-group-ids"`
	SecurityGroups      string `json:"security-groups"`
	SubnetID            string `json:"subnet-id"`
	SubnetIpv4CidrBlock string `json:"subnet-ipv4-cidr-block"`
	VpcID               string `json:"vpc-id"`
	VpcIpv4CidrBlock    string `json:"vpc-ipv4-cidr-block"`
	VpcIpv4CidrBlocks   string `json:"vpc-ipv4-cidr-blocks"`
}

type EC2 struct {
	AmiID              string `json:"ami-id"`
	AmiLaunchIndex     string `json:"ami-launch-index"`
	AmiManifestPath    string `json:"ami-manifest-path"`
	BlockDeviceMapping struct {
		Ami  string `json:"ami"`
		Root string `json:"root"`
	} `json:"block-device-mapping"`
	Events struct {
		Maintenance struct {
			History   string `json:"history"`
			Scheduled string `json:"scheduled"`
		} `json:"maintenance"`
	} `json:"events"`
	Hostname            string `json:"hostname"`
	IdentityCredentials struct {
		Ec2 struct {
			Info                string `json:"info"`
			SecurityCredentials struct {
				Ec2Instance string `json:"ec2-instance"`
			} `json:"security-credentials"`
		} `json:"ec2"`
	} `json:"identity-credentials"`
	InstanceAction    string `json:"instance-action"`
	InstanceID        string `json:"instance-id"`
	InstanceLifeCycle string `json:"instance-life-cycle"`
	InstanceType      string `json:"instance-type"`
	LocalHostname     string `json:"local-hostname"`
	LocalIpv4         string `json:"local-ipv4"`
	Mac               string `json:"mac"`
	Network           struct {
		Interfaces struct {
			Macs struct {
			} `json:"macs"`
		} `json:"interfaces"`
	} `json:"network"`
	Placement struct {
		AvailabilityZone   string `json:"availability-zone"`
		AvailabilityZoneID string `json:"availability-zone-id"`
		Region             string `json:"region"`
	} `json:"placement"`
	Profile        string `json:"profile"`
	PublicHostname string `json:"public-hostname"`
	PublicIpv4     string `json:"public-ipv4"`
	PublicKeys     struct {
		ZeroSusant string `json:"0=Susant"`
	} `json:"public-keys"`
	ReservationID  string `json:"reservation-id"`
	SecurityGroups string `json:"security-groups"`
	Services       struct {
		Domain    string `json:"domain"`
		Partition string `json:"partition"`
	} `json:"services"`
}

type EC2Data struct {
	system  EC2MetaData
	network EC2MetaData
	macs    map[string]EC2MetaData
}

type EC2MetaData interface{}

func fetchCloudMetadataByURL(url string) []string {
	resp, err := http.Get(url)
	if err != nil {
		log.Errorf("Failed to fetch Instance metadata from endpoint: '%v'", err)
		return nil
	}
	defer resp.Body.Close()

	data := make([]string, 0)
	s := bufio.NewScanner(resp.Body)

	m := make(map[string]bool)
	for s.Scan() {
		line := s.Text()
		if strings.HasSuffix(url, "local-ipv4s") {
			m[strings.TrimRight(line, "\n")] = true
			data = append(data, line)
		} else {
			data = append(data, strings.TrimRight(line, "\n"))
		}
	}

	if len(m) <= 0 {
		return data
	} else {
		b := new(bytes.Buffer)
		for key := range m {
			fmt.Fprintf(b, "%v,", key)
		}
		return strings.Fields(strings.TrimRight(b.String(), ","))
	}
}

func fetchCloudMetadataLoop(url string) EC2MetaData {
	m := make(map[string]interface{})
	data := fetchCloudMetadataByURL(url)
	for _, line := range data {
		switch {
		default:
			m[line] = fetchCloudMetadataByURL(url + line)[0]
		case strings.HasSuffix(line, "/"):
			m[line[:len(line)-1]] = fetchCloudMetadataLoop(url + line)
		case strings.HasSuffix(url, "public-keys/"):
			keyId := strings.SplitN(line, "=", 2)[0]
			m[line] = fetchCloudMetadataByURL(url + keyId + "/openssh-key")[0]
		}
	}

	return m
}

func fetchMACAddresses(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New("unexpected response when fetching instance MAC addresses")
	}
	defer resp.Body.Close()

	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	s := strings.Replace(string(raw), "/\n", " ", -1)

	return strings.Fields(strings.TrimRight(s, "/")), nil
}

func FetchCloudMetadata(m *cloud.CloudManager) error {
	macs, err := fetchMACAddresses("http://" + EC2Endpoint + EC2MetaDataURLBase + EC2MetaDataNetwork)
	if err != nil {
		return err
	}

	s := fetchCloudMetadataLoop("http://" + EC2Endpoint + EC2MetaDataURLBase)
	n := fetchCloudMetadataLoop("http://" + EC2Endpoint + EC2MetaDataURLBase + EC2MetaDataNetwork)

	d := EC2Data{
		system:  s,
		network: n,
		macs:    make(map[string]EC2MetaData),
	}

	for _, t := range macs {
		mac := fetchCloudMetadataLoop("http://" + EC2Endpoint + EC2MetaDataURLBase + EC2MetaDataNetwork + t + "/")
		if err != nil {
			return err
		}

		d.macs[t] = mac
	}

	m.MetaData = d
	return nil
}

func parseIpv4AddressesFromMetadata(addresses string, cidr string) (map[string]bool, error) {
	m := make(map[string]bool)

	prefix := strings.Split(cidr, "/")[1]
	s := strings.Split(addresses, ",")
	for _, t := range s {

		a := t + "/" + prefix
		m[a] = true
	}

	return m, nil
}

// AddressConfigureCloudMetadata configures link address
func ConfigureCloudMetadataAddress(m *cloud.CloudManager) error {
	links, err := network.AcquireLinks()
	if err != nil {
		return err
	}

	d := m.MetaData.(EC2Data)
	for k, v := range d.macs {
		j, err := json.Marshal(v)
		if err != nil {
			return err
		}

		n := Mac{}
		json.Unmarshal([]byte(j), &n)

		l, ok := links.LinksByMAC[k]
		if !ok {
			log.Errorf("Failed to find link having MAC Address='%+v': %+v", k, err)
			continue
		}

		existingAddresses, err := network.GetIPv4Addreses(l.Name)
		if err != nil {
			log.Errorf("Failed to fetch Ip addresses of link='%+v' ifindex='%+v': %+v", l.Name, l.Ifindex, err)
			continue
		}

		newAddresses, err := parseIpv4AddressesFromMetadata(n.LocalIpv4S, n.SubnetIpv4CidrBlock)
		if err != nil {
			log.Errorf("Failed to fetch Ip addresses of link='%+v' ifindex='%+v' from metadata: %+v", l.Name, l.Ifindex, err)
			continue
		}

		eq := reflect.DeepEqual(existingAddresses, newAddresses)
		if eq {
			log.Debugf("Existing addresses='%+v' and new addresses='%+v' received from AWS(EC2) endpoint are same. Skipping ...", existingAddresses, newAddresses)
			continue
		}

		for i := range newAddresses {
			_, ok = existingAddresses[i]
			if !ok {
				err = network.SetAddress(l.Name, i)
				if err != nil {
					log.Errorf("Failed to add address='%+v' to link='%+v' ifindex='%d': +v", i, l.Name, l.Ifindex, err)
					continue
				}

				log.Infof("Successfully added address='%+v on link='%+v' ifindex='%d'", i, l.Name, l.Ifindex)
			}
		}
	}

	return nil
}

func routerGetEC2(rw http.ResponseWriter, r *http.Request) {
	d := cloud.GetConext().MetaData
	ec2 := d.(EC2Data)

	switch r.Method {
	case "GET":
		utils.JSONResponse(ec2.system, rw)
	default:
	}
}

// RegisterRouterAzure Register Azure APIs with router
func RegisterRouterEC2(router *mux.Router) {
	router.HandleFunc("/system", routerGetEC2)
}
