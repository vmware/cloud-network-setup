// Copyright 2021 VMware, Inc.
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

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cloud-network-setup/pkg/network"
	"github.com/cloud-network-setup/pkg/utils"
)

const (
	// EC2 Metadata endpoint.
	EC2Endpoint string = "169.254.169.254"

	//EC2 Metadata URL Base
	EC2MetaDataURLBase string = "/latest/meta-data/"

	//EC2 Metadata mac URL Base
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
	resp, err := http.Get(url)
	if err != nil {
		log.Errorf("Failed to fetch instance metadata from endpoint: '%v'", err)
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

func fetchMetadata(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, errors.New("unexpected response when fetching instance credentials")
	}
	defer resp.Body.Close()

	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return raw, nil
}

func (ec2 *EC2) FetchCloudMetadata() error {
	macs, err := fetchMACAddresses("http://" + EC2Endpoint + EC2MetaDataURLBase + EC2MetaDataNetwork)
	if err != nil {
		return err
	}

	c, err := fetchMetadata("http://" + EC2Endpoint + EC2MetaDataURLBase + EC2MetaDataIdentityCredentials)
	if err != nil {
		return err
	}

	doc, err := fetchMetadata("http://" + EC2Endpoint + EC2MetaDataDynamicIdentityDocument + "document")
	if err != nil {
		return err
	}

	pkcs7, err := fetchMetadata("http://" + EC2Endpoint + EC2MetaDataDynamicIdentityDocument + "pkcs7")
	if err != nil {
		return err
	}

	signature, err := fetchMetadata("http://" + EC2Endpoint + EC2MetaDataDynamicIdentityDocument + "signature")
	if err != nil {
		return err
	}

	rsa2048, err := fetchMetadata("http://" + EC2Endpoint + EC2MetaDataDynamicIdentityDocument + "rsa2048")
	if err != nil {
		return err
	}

	s := fetchCloudMetadataLoop("http://" + EC2Endpoint + EC2MetaDataURLBase)
	n := fetchCloudMetadataLoop("http://" + EC2Endpoint + EC2MetaDataURLBase + EC2MetaDataNetwork)

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

func configureNetworkForPrimary(m *Enviroment) error {
	linkList, err := netlink.LinkList()
	if err != nil {
		return err
	}

	for _, link := range linkList {
		if link.Attrs().Name == "lo" {
			continue
		}

		if link.Attrs().Index == 2 {
			gw, err := network.GetDefaultIpv4GatewayByLink(link.Attrs().Index)
			if err != nil {
				log.Infof("Failed to find default gateway for the link ifindex='%s': '%+v'", link.Attrs().Index, err)
				return err
			}

			err = network.AddRoute(link.Attrs().Index, m.routeTable+link.Attrs().Index, gw)
			if err != nil {
				log.Errorf("Failed to add default gateway='%+v' for link ifindex='%+v' '%+v' table='%d': %+v", gw, link.Attrs().Index, err)
				return err
			} else {
				log.Debugf("Successfully added default gateway='%+v' for link  ifindex='%+v'", gw, link.Attrs().Index)
			}

			addresses, err := network.GetIPv4Addreses(link.Attrs().Name)
			if err != nil {
				return err
			}

			for addr := range addresses {
				a := strings.TrimSuffix(strings.SplitAfter(addr, "/")[0], "/")

				from := &network.IPRoutingRule{
					From:  a,
					Table: m.routeTable + link.Attrs().Index,
				}

				err := network.AddRoutingPolicyRule(from)
				if err != nil {
					log.Errorf("Failed to add routing policy rule 'from' for link ifindex='%+v': %+v", link.Attrs().Index, err)
					return err
				} else {
					log.Debugf("Successfully added routing policy rule 'from' for link ifindex='%+v'", link.Attrs().Index)
				}
			}
		}
	}

	return nil
}

func (ec2 *EC2) ConfigureNetworkFromCloudMeta(m *Enviroment) error {
	for mac, v := range ec2.macs {
		j, err := json.Marshal(v)
		if err != nil {
			return err
		}

		n := EC2MAC{}
		json.Unmarshal([]byte(j), &n)

		l, ok := m.links.LinksByMAC[mac]
		if !ok {
			log.Errorf("Failed to find link having MAC Address='%+v'", mac)
			continue
		}

		newAddresses, err := parseIpv4AddressesFromMetadata(n.LocalIpv4S, n.SubnetIpv4CidrBlock)
		if err != nil {
			log.Errorf("Failed to fetch Ip addresses of link='%+v' ifindex='%+v' from metadata: %+v", l.Name, l.Ifindex, err)
			continue
		}

		m.configureNetwork(&l, newAddresses)

		// EC2's primary interface looses connectivity if the second interface gets configured
		// Hence add a default route for the primary interface too and rules for each address

		configureNetworkForPrimary(m)

	}

	return nil
}

func (ec2 *EC2) SaveCloudMetadata() error {
	err := utils.CreateAndSaveJSON("/run/cloud-network-setup/system", ec2.system)
	if err != nil {
		log.Errorf("Failed to write system file: %+v", err)
		return err
	}

	return nil
}

func (ec2 *EC2) SaveCloudMetadataIdentityCredentials() error {
	err := utils.CreateAndSaveJSON("/run/cloud-network-setup/provider/ec2/credentials", ec2.credentials)
	if err != nil {
		log.Errorf("Failed to save instance credentials metadata 'credentials': %+v", err)
	}

	err = utils.CreateAndSaveJSON("/run/cloud-network-setup/provider/ec2/document", ec2.document)
	if err != nil {
		log.Errorf("Failed to save instance identity metadata 'document': %+v", err)
		return err
	}

	err = utils.CreateAndSaveJSON("/run/cloud-network-setup/provider/ec2/pkcs7", ec2.pkcs7)
	if err != nil {
		log.Errorf("Failed to save instance identity metadata 'pkcs7': %+v", err)
		return err
	}

	err = utils.CreateAndSaveJSON("/run/cloud-network-setup/provider/ec2/signature", ec2.signature)
	if err != nil {
		log.Errorf("Failed to save instance identity metadata 'signature': %+v", err)
		return err
	}

	err = utils.CreateAndSaveJSON("/run/cloud-network-setup/provider/ec2/rsa2048", ec2.rsa2048)
	if err != nil {
		log.Errorf("Failed to save instance identity metadata 'rsa2048': %+v", err)
		return err
	}

	return nil
}

func (ec2 *EC2) LinkSaveCloudMetadata() error {
	links, err := network.AcquireLinks()
	if err != nil {
		return err
	}

	for k, v := range ec2.macs {
		l, ok := links.LinksByMAC[k]
		if !ok {
			log.Errorf("Failed to find link having MAC Address='%+v': %+v", k, err)
			continue
		}

		j, _ := json.Marshal(v)

		n := EC2MAC{}
		json.Unmarshal([]byte(j), &n)

		file := path.Join("/run/cloud-network-setup/links", strconv.Itoa(l.Ifindex))
		err = utils.CreateAndSaveJSON(file, n)
		if err != nil {
			log.Errorf("Failed to write state file '%+v' for link='%+v'': %+v", file, l.Name, err)
			return err
		}
	}

	return nil
}

func (e *Enviroment) routerGetEC2System(rw http.ResponseWriter, r *http.Request) {
	utils.JSONResponse(e.ec2.system, rw)
}

func (e *Enviroment) routerGetEC2Network(rw http.ResponseWriter, r *http.Request) {
	utils.JSONResponse(e.ec2.network, rw)
}

func (e *Enviroment) routerGetEC2Credentials(rw http.ResponseWriter, r *http.Request) {
	utils.JSONResponse(e.ec2.credentials, rw)
}

func (e *Enviroment) routerGetEC2DynamicInstanceIdentity(rw http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "document") {
		utils.JSONResponse(e.ec2.document, rw)
	} else if strings.HasSuffix(r.URL.Path, "pkcs7") {
		utils.JSONResponse(e.ec2.pkcs7, rw)
	} else if strings.HasSuffix(r.URL.Path, "signature") {
		utils.JSONResponse(e.ec2.signature, rw)
	} else if strings.HasSuffix(r.URL.Path, "rsa2048") {
		utils.JSONResponse(e.ec2.rsa2048, rw)
	}
}

func RegisterRouterEC2(r *mux.Router, e *Enviroment) {
	r.HandleFunc("/system", e.routerGetEC2System).Methods("GET")
	r.HandleFunc("/network", e.routerGetEC2Network).Methods("GET")
	r.HandleFunc("/credentials", e.routerGetEC2Credentials).Methods("GET")
	r.HandleFunc("/dynamicinstanceidentity/{category}", e.routerGetEC2DynamicInstanceIdentity).Methods("GET")
}
