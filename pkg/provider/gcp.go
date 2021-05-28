// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"encoding/json"
	"net"
	"net/http"
	"path"
	"reflect"
	"strconv"

	"github.com/go-resty/resty/v2"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/cloud-network-setup/pkg/network"
	"github.com/cloud-network-setup/pkg/utils"
)

const (
	// GCP REST Endpoint Metadata endpoint.
	GCPIMDSRESTEndpoint string = "metadata.google.internal"

	// GCP Metadta URLBase
	GCPMetadtaURLBase string = "/computeMetadata/v1/?recursive=true"
)

type GCP struct {
	meta GCPMetaData
}

type GCPMetaData struct {
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

func NewGCP() *GCP {
	return &GCP{}
}

func (g *GCP) FetchCloudMetadata() error {
	client := resty.New()
	client.SetHeader("Metadata-Flavor", "Google")

	resp, err := client.R().Get("http://" + GCPIMDSRESTEndpoint + GCPMetadtaURLBase)
	if resp.StatusCode() != 200 {
		log.Errorf("Failed to fetch metadata from GCP Instance Metadata Service: '%+v'", resp.StatusCode())
		return err
	}

	json.Unmarshal(resp.Body(), &g.meta)
	return nil
}

func (g *GCP) parseIpv4AddressesFromMetadataByMac(mac string) (map[string]bool, error) {
	m := make(map[string]bool)

	for i := 0; i < len(g.meta.Instance.Networkinterfaces); i++ {
		if mac == g.meta.Instance.Networkinterfaces[i].Mac {
			ip := g.meta.Instance.Networkinterfaces[i].IP
			mask := net.IPMask(net.ParseIP(g.meta.Instance.Networkinterfaces[i].Subnetmask).To4())
			prefix, _ := mask.Size()
			k := strconv.Itoa(prefix)

			a := ip + "/" + k
			m[a] = true

			for _, w := range g.meta.Instance.Networkinterfaces[i].Ipaliases {
				m[w] = true
			}
		}
	}

	return m, nil
}

func (g *GCP) ConfigureCloudMetadataAddress() error {
	links, err := network.AcquireLinks()
	if err != nil {
		return err
	}

	for i := 0; i < len(g.meta.Instance.Networkinterfaces); i++ {
		l, ok := links.LinksByMAC[g.meta.Instance.Networkinterfaces[i].Mac]
		if !ok {
			log.Errorf("Failed to find link having MAC Address='%+v'", g.meta.Instance.Networkinterfaces[i].Mac)
			continue
		}

		existingAddresses, err := network.GetIPv4Addreses(l.Name)
		if err != nil {
			log.Errorf("Failed to fetch Ip addresses of link='%+v' ifindex='%+v': %+v", l.Name, l.Ifindex, err)
			continue
		}

		newAddresses, err := g.parseIpv4AddressesFromMetadataByMac(g.meta.Instance.Networkinterfaces[i].Mac)
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

func (g *GCP) SaveCloudMetadata() error {
	err := utils.CreateAndSaveJSON("/run/cloud-network-setup/system", g.meta)
	if err != nil {
		log.Errorf("Failed to write system file: %+v", err)
		return err
	}

	return nil
}

func (g *GCP) LinkSaveCloudMetadata() error {
	links, err := network.AcquireLinks()
	if err != nil {
		return err
	}

	for i := 0; i < len(g.meta.Instance.Networkinterfaces); i++ {
		l, b := links.LinksByMAC[g.meta.Instance.Networkinterfaces[i].Mac]
		if !b {
			continue
		}

		link := g.meta.Instance.Networkinterfaces[i]
		err = utils.CreateAndSaveJSON(path.Join("/run/cloud-network-setup/links", strconv.Itoa(l.Ifindex)), link)
		if err != nil {
			log.Errorf("Failed to write link state file link='%+v': %+v", l.Name, err)
			return err
		}
	}

	return nil
}

func (e *Enviroment) routerGetGCP(rw http.ResponseWriter, r *http.Request) {
	utils.JSONResponse(e.gcp.meta, rw)

}

func RegisterRouterGCP(r *mux.Router, e *Enviroment) {
	r.HandleFunc("/network", e.routerGetGCP).Methods("GET")
	r.HandleFunc("/system", e.routerGetGCP).Methods("GET")
}