// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path"
	"reflect"
	"strconv"

	"github.com/go-resty/resty/v2"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/cloud-network-setup/pkg/cloud"
	"github.com/cloud-network-setup/pkg/network"
	"github.com/cloud-network-setup/pkg/utils"
)

const (
	// GCP REST Endpoint Metadata endpoint.
	GCPIMDSRESTEndpoint string = "metadata.google.internal"

	// GCP Metadta URLBase
	GCPMetadtaURLBase string = "/computeMetadata/v1/?recursive=true"
)

// GCP compute metadata
type GCP struct {
	Instance struct {
		Attributes struct {
		} `json:"attributes"`
		Cpuplatform string `json:"cpuPlatform"`
		Description string `json:"description"`
		Disks       []struct {
			Devicename string `json:"deviceName"`
			Index      int    `json:"index"`
			Interface  string `json:"interface"`
			Mode       string `json:"mode"`
			Type       string `json:"type"`
		} `json:"disks"`
		Guestattributes struct {
		} `json:"guestAttributes"`
		Hostname             string `json:"hostname"`
		ID                   int64  `json:"id"`
		Image                string `json:"image"`
		Legacyendpointaccess struct {
			Zero1   int `json:"0.1"`
			V1Beta1 int `json:"v1beta1"`
		} `json:"legacyEndpointAccess"`
		Machinetype       string `json:"machineType"`
		Maintenanceevent  string `json:"maintenanceEvent"`
		Name              string `json:"name"`
		Networkinterfaces []struct {
			Accessconfigs []struct {
				Externalip string `json:"externalIp"`
				Type       string `json:"type"`
			} `json:"accessConfigs"`
			Dnsservers        []string `json:"dnsServers"`
			Forwardedips      []string `json:"forwardedIps"`
			Gateway           string   `json:"gateway"`
			IP                string   `json:"ip"`
			Ipaliases         []string `json:"ipAliases"`
			Mac               string   `json:"mac"`
			Mtu               int      `json:"mtu"`
			Network           string   `json:"network"`
			Subnetmask        string   `json:"subnetmask"`
			Targetinstanceips []string `json:"targetInstanceIps"`
		} `json:"networkInterfaces"`
		Preempted        string `json:"preempted"`
		Remainingcputime int    `json:"remainingCpuTime"`
		Scheduling       struct {
			Automaticrestart  string `json:"automaticRestart"`
			Onhostmaintenance string `json:"onHostMaintenance"`
			Preemptible       string `json:"preemptible"`
		} `json:"scheduling"`
		Serviceaccounts struct {
			Three8191186391ComputeDeveloperGserviceaccountCom struct {
				Aliases []string `json:"aliases"`
				Email   string   `json:"email"`
				Scopes  []string `json:"scopes"`
			} `json:"38191186391-compute@developer.gserviceaccount.com"`
			Default struct {
				Aliases []string `json:"aliases"`
				Email   string   `json:"email"`
				Scopes  []string `json:"scopes"`
			} `json:"default"`
		} `json:"serviceAccounts"`
		Tags         []interface{} `json:"tags"`
		Virtualclock struct {
			Drifttoken string `json:"driftToken"`
		} `json:"virtualClock"`
		Zone string `json:"zone"`
	} `json:"instance"`
	Oslogin struct {
		Authenticate struct {
			Sessions struct {
			} `json:"sessions"`
		} `json:"authenticate"`
	} `json:"oslogin"`
	Project struct {
		Attributes struct {
			GkeWfu123F8B0D4Cidr string `json:"gke-wfu1-23f8b0d4-cidr"`
			GkeWfu186B63F6DCidr string `json:"gke-wfu1-86b63f6d-cidr"`
			SSHKeys             string `json:"ssh-keys"`
			Sshkeys             string `json:"sshKeys"`
		} `json:"attributes"`
		Numericprojectid int64  `json:"numericProjectId"`
		Projectid        string `json:"projectId"`
	} `json:"project"`
}

func FetchCloudMetadata(m *cloud.CloudManager) error {
	client := resty.New()
	client.SetHeader("Metadata-Flavor", "Google")

	resp, err := client.R().Get("http://" + GCPIMDSRESTEndpoint + GCPMetadtaURLBase)
	if resp.StatusCode() != 200 {
		log.Errorf("Failed to fetch metadata from GCP Instance Metadata Service: '%+v'", resp.StatusCode())
		return err
	}

	d := GCP{}
	json.Unmarshal(resp.Body(), &d)
	m.MetaData = d

	return nil
}

func parseIpv4AddressesFromMetadataByMac(mac string, g *GCP) (map[string]bool, error) {
	m := make(map[string]bool)

	for i := 0; i < len(g.Instance.Networkinterfaces); i++ {
		if mac == g.Instance.Networkinterfaces[i].Mac {
			ip := g.Instance.Networkinterfaces[i].IP
			mask := net.IPMask(net.ParseIP(g.Instance.Networkinterfaces[i].Subnetmask).To4())
			prefix, _ := mask.Size()
			k := strconv.Itoa(prefix)

			a := ip + "/" + k
			m[a] = true

			for _, w := range g.Instance.Networkinterfaces[i].Ipaliases {
				m[w] = true
			}
		}
	}

	return m, nil
}

func ConfigureCloudMetadataAddress(m *cloud.CloudManager) error {
	g := m.MetaData.(GCP)

	links, err := network.AcquireLinks()
	if err != nil {
		return err
	}

	for i := 0; i < len(g.Instance.Networkinterfaces); i++ {
		l, ok := links.LinksByMAC[g.Instance.Networkinterfaces[i].Mac]
		if !ok {
			log.Errorf("Failed to find link having MAC Address='%+v'", g.Instance.Networkinterfaces[i].Mac)
			continue
		}

		existingAddresses, err := network.GetIPv4Addreses(l.Name)
		if err != nil {
			log.Errorf("Failed to fetch Ip addresses of link='%+v' ifindex='%+v': %+v", l.Name, l.Ifindex, err)
			continue
		}

		newAddresses, err := parseIpv4AddressesFromMetadataByMac(g.Instance.Networkinterfaces[i].Mac, &g)
		if err != nil {
			log.Errorf("Failed to fetch Ip addresses of link='%+v' ifindex='%+v' from metadata: %+v", l.Name, l.Ifindex, err)
			continue
		}

		eq := reflect.DeepEqual(existingAddresses, newAddresses)
		if eq {
			log.Debugf("Existing addresses='%+v' and new addresses='%+v' received from GCP endpoint are same. Skipping ...", existingAddresses, newAddresses)
			continue
		}

		// Purge old addresses
		for i := range existingAddresses {
			_, ok = newAddresses[i]
			if !ok {
				err = network.RemoveIPAddress(l.Name, i)
				if err != nil {
					log.Errorf("Failed to remove address='%+v' from link='%+v': '%+v'", i, l.Name, l.Ifindex, err)
					continue
				} else {
					log.Infof("Successfully removed address='%+v on link='%+v' ifindex='%d'", i, l.Name, l.Ifindex)
				}
			}
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

func SaveCloudMetadata(m *cloud.CloudManager) error {
	f, err := os.OpenFile("/run/cloud-network-setup/system", os.O_RDWR, 0644)
	if err != nil {
		log.Errorf("Failed to open system file '/run/cloud-network-setup/system': %+v", err)
		return err
	}
	defer f.Close()

	k := m.MetaData.(GCP)

	d, _ := json.MarshalIndent(k, "", " ")
	f.Write(d)

	return nil
}

func LinkSaveCloudMetadata(m *cloud.CloudManager) error {
	d := m.MetaData.(GCP)

	links, err := network.AcquireLinks()
	if err != nil {
		return err
	}

	for i := 0; i < len(d.Instance.Networkinterfaces); i++ {
		l, b := links.LinksByMAC[d.Instance.Networkinterfaces[i].Mac]
		if !b {
			continue
		}

		s := strconv.Itoa(l.Ifindex)
		file := path.Join("/run/cloud-network-setup/links", s)
		f, err := os.OpenFile(file, os.O_RDWR, 0644)
		if err != nil {
			log.Errorf("Failed to open state file for link file '%+v': %+v", file, err)
			return err
		}
		defer f.Close()

		link := d.Instance.Networkinterfaces[i]

		d, _ := json.MarshalIndent(link, "", " ")
		f.Write(d)
	}

	return nil
}

func routerGetGCP(rw http.ResponseWriter, r *http.Request) {
	m := cloud.GetConext().MetaData.(GCP)

	switch r.Method {
	case "GET":
		utils.JSONResponse(m, rw)
	default:
	}
}

func RegisterRouterGCP(router *mux.Router) {
	router.HandleFunc("/network", routerGetGCP)
	router.HandleFunc("/system", routerGetGCP)
}
