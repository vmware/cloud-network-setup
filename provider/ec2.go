// Copyright 2024 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/vmware/cloud-network-setup/conf"
	"github.com/vmware/cloud-network-setup/pkg/network"
	"github.com/vmware/cloud-network-setup/pkg/system"
	"github.com/vmware/cloud-network-setup/pkg/web"
)

const (
	// EC2 Metadata endpoint.
	EC2Endpoint string = "169.254.169.254"

	// EC2 Metadata URL Base
	EC2MetaDataURLBase string = "/latest/meta-data/"

	// EC2 Metadata mac URL Base
	EC2MetaDataNetwork string = "network/interfaces/macs/"

	EC2MetaDataIdentityCredentials     string = "identity-credentials/ec2/security-credentials/ec2-instance/"
	EC2MetaDataDynamicIdentityDocument string = "/latest/dynamic/instance-identity/"
)

type EC2Document struct {
	Accountid               string   `json:"accountId"`
	Architecture            string   `json:"architecture"`
	Availabilityzone        string   `json:"availabilityZone"`
	Billingproducts         []string `json:"billingProducts"`
	Devpayproductcodes      []string `json:"devpayProductCodes"`
	Marketplaceproductcodes []string `json:"marketplaceProductCodes"`
	Imageid                 string   `json:"imageId"`
	Instanceid              string   `json:"instanceId"`
	Instancetype            string   `json:"instanceType"`
	Kernelid                string   `json:"kernelId"`
	Pendingtime             string   `json:"pendingTime"`
	Privateip               string   `json:"privateIp"`
	Ramdiskid               string   `json:"ramdiskId"`
	Region                  string   `json:"region"`
	Version                 string   `json:"version"`
}

type EC2Credentials struct {
	Code            string `json:"Code"`
	Lastupdated     string `json:"LastUpdated"`
	Type            string `json:"Type"`
	Accesskeyid     string `json:"AccessKeyId"`
	Secretaccesskey string `json:"SecretAccessKey"`
	Token           string `json:"Token"`
	Expiration      string `json:"Expiration"`
}

type EC2MAC struct {
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

type EC2System struct {
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
	Hostname          string `json:"hostname"`
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
	} `json:"public-keys"`
	ReservationID  string `json:"reservation-id"`
	SecurityGroups string `json:"security-groups"`
	Services       struct {
		Domain    string `json:"domain"`
		Partition string `json:"partition"`
	} `json:"services"`
}

type EC2 struct {
	system      map[string]interface{}
	network     map[string]interface{}
	credentials EC2Credentials
	document    EC2Document
	pkcs7       string
	signature   string
	rsa2048     string

	macs map[string]interface{}
}

func NewEC2() *EC2 {
	return &EC2{}
}

func fetchCloudMetadataByURL(url string) []string {
	client := http.Client{
		Timeout: time.Duration(conf.DefaultHttpRequestTimeout) * time.Millisecond,
	}

	resp, err := client.Get(url)
	if err != nil {
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

func fetchCloudMetadataLoop(url string) map[string]interface{} {
	m := make(map[string]interface{})

	data := fetchCloudMetadataByURL(url)
	for _, line := range data {
		switch {
		case strings.HasSuffix(line, "/"):
			m[line[:len(line)-1]] = fetchCloudMetadataLoop(url + line)
		case strings.HasSuffix(url, "public-keys/"):
			keyId := strings.SplitN(line, "=", 2)[0]
			m[line] = fetchCloudMetadataByURL(url + keyId + "/openssh-key")[0]
		default:
			m[line] = fetchCloudMetadataByURL(url + line)[0]
		}
	}

	return m
}

func fetchMACAddresses(url string) ([]string, error) {
	client := http.Client{
		Timeout: time.Duration(conf.DefaultHttpRequestTimeout) * time.Millisecond,
	}

	resp, err := client.Get(url)
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

func (ec2 *EC2) FetchCloudMetadata() error {
	macs, err := fetchMACAddresses("http://" + EC2Endpoint + EC2MetaDataURLBase + EC2MetaDataNetwork)
	if err != nil {
		return err
	}

	c, err := web.Dispatch("http://"+EC2Endpoint+EC2MetaDataURLBase+EC2MetaDataIdentityCredentials, nil)
	if err != nil {
		return err
	}

	doc, err := web.Dispatch("http://"+EC2Endpoint+EC2MetaDataDynamicIdentityDocument+"document", nil)
	if err != nil {
		return err
	}

	pkcs7, err := web.Dispatch("http://"+EC2Endpoint+EC2MetaDataDynamicIdentityDocument+"pkcs7", nil)
	if err != nil {
		return err
	}

	signature, err := web.Dispatch("http://"+EC2Endpoint+EC2MetaDataDynamicIdentityDocument+"signature", nil)
	if err != nil {
		return err
	}

	rsa2048, err := web.Dispatch("http://"+EC2Endpoint+EC2MetaDataDynamicIdentityDocument+"rsa2048", nil)
	if err != nil {
		return err
	}

	s := fetchCloudMetadataLoop("http://" + EC2Endpoint + EC2MetaDataURLBase)
	if len(s) <= 0 {
		return errors.New("failed to fetch metadata")
	}
	n := fetchCloudMetadataLoop("http://" + EC2Endpoint + EC2MetaDataURLBase + EC2MetaDataNetwork)
	if len(s) <= 0 {
		return errors.New("failed to fetch metadata")
	}

	var cred EC2Credentials
	json.Unmarshal(c, &cred)

	var t EC2Document
	json.Unmarshal(doc, &t)

	ec2.system = s
	ec2.network = n
	ec2.credentials = cred
	ec2.document = t
	ec2.pkcs7 = string(pkcs7)
	ec2.signature = string(signature)
	ec2.rsa2048 = string(rsa2048)
	ec2.macs = make(map[string]interface{})

	for _, t := range macs {
		mac := fetchCloudMetadataLoop("http://" + EC2Endpoint + EC2MetaDataURLBase + EC2MetaDataNetwork + t + "/")
		if err != nil {
			return err
		}

		ec2.macs[t] = mac
	}

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

func (ec2 *EC2) ConfigureNetworkFromCloudMeta(m *Environment) error {
	for mac, v := range ec2.macs {
		j, err := json.Marshal(v)
		if err != nil {
			return err
		}

		n := EC2MAC{}
		json.Unmarshal([]byte(j), &n)

		link, ok := m.Links.LinksByMAC[mac]
		if !ok {
			log.Errorf("Failed to find link having MAC Address='%+v'", mac)
			continue
		}

		newAddresses, err := parseIpv4AddressesFromMetadata(n.LocalIpv4S, n.SubnetIpv4CidrBlock)
		if err != nil {
			log.Errorf("Failed to fetch Ip addresses of link='%+v' ifindex='%+v' from metadata: %+v", link.Name, link.Ifindex, err)
			continue
		}

		if err = m.configureNetwork(&link, newAddresses); err != nil {
			continue
		}

		// EC2's primary interface looses connectivity if the second interface gets configured.
		// Hence add a default route for the primary interface too and rules for each address
		if err := network.ConfigureByIndex(2); err != nil {
			log.Errorf("Failed to configure network for link='%+v' ifindex='%+v': %+v", link.Name, link.Ifindex, err)
		}
	}

	return nil
}

func (ec2 *EC2) SaveCloudMetadata() error {
	if err := system.CreateAndSaveJSON(conf.SystemState, ec2.system); err != nil {
		return err
	}

	return nil
}

func (ec2 *EC2) SaveCloudMetadataIdentityCredentials() error {
	if err := system.CreateAndSaveJSON(conf.ProviderStateDir+"/ec2/credentials", ec2.credentials); err != nil {
		return err
	}

	if err := system.CreateAndSaveJSON(conf.ProviderStateDir+"/ec2/document", ec2.document); err != nil {
		return err
	}

	if err := system.CreateAndSaveJSON(conf.ProviderStateDir+"/ec2/pkcs7", ec2.pkcs7); err != nil {
		return err
	}

	if err := system.CreateAndSaveJSON(conf.ProviderStateDir+"/ec2/signature", ec2.signature); err != nil {
		return err
	}

	if err := system.CreateAndSaveJSON(conf.ProviderStateDir+"/ec2/rsa2048", ec2.rsa2048); err != nil {
		return err
	}

	return nil
}

func (ec2 *EC2) LinkSaveCloudMetadata(m *Environment) error {
	for k, v := range ec2.macs {
		l, ok := m.Links.LinksByMAC[k]
		if !ok {
			log.Errorf("Failed to find link having MAC Address='%s'", k)
			continue
		}

		j, _ := json.Marshal(v)

		n := EC2MAC{}
		json.Unmarshal([]byte(j), &n)

		f := path.Join(conf.LinkStateDir, strconv.Itoa(l.Ifindex))
		if err := system.CreateAndSaveJSON(f, n); err != nil {
			log.Errorf("Failed to write link state '%s' for link='%+v'': %+v", f, l.Name, err)
			return err
		}
	}

	return nil
}

func (m *Environment) routerGetEC2System(rw http.ResponseWriter, r *http.Request) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	web.JSONResponse(m.ec2.system, rw)
}

func (m *Environment) routerGetEC2Network(rw http.ResponseWriter, r *http.Request) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	web.JSONResponse(m.ec2.network, rw)
}

func (m *Environment) routerGetEC2Credentials(rw http.ResponseWriter, r *http.Request) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	web.JSONResponse(m.ec2.credentials, rw)
}

func (m *Environment) routerGetEC2DynamicInstanceIdentity(rw http.ResponseWriter, r *http.Request) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	if strings.HasSuffix(r.URL.Path, "document") {
		web.JSONResponse(m.ec2.document, rw)
	} else if strings.HasSuffix(r.URL.Path, "pkcs7") {
		web.JSONResponse(m.ec2.pkcs7, rw)
	} else if strings.HasSuffix(r.URL.Path, "signature") {
		web.JSONResponse(m.ec2.signature, rw)
	} else if strings.HasSuffix(r.URL.Path, "rsa2048") {
		web.JSONResponse(m.ec2.rsa2048, rw)
	}
}

func RegisterRouterEC2(r *mux.Router, m *Environment) {
	r.HandleFunc("/system", m.routerGetEC2System).Methods("GET")
	r.HandleFunc("/network", m.routerGetEC2Network).Methods("GET")
	r.HandleFunc("/credentials", m.routerGetEC2Credentials).Methods("GET")
	r.HandleFunc("/dynamicinstanceidentity/{category}", m.routerGetEC2DynamicInstanceIdentity).Methods("GET")
}
