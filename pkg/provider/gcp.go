// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path"
	"strconv"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/cloud-network-setup/pkg/conf"
	"github.com/cloud-network-setup/pkg/system"
	"github.com/cloud-network-setup/pkg/web"
)

const (
	// GCP REST Endpoint Metadata endpoint.
	GCPIMDSRESTEndpoint string = "metadata.google.internal"

	// GCP Metadata URLBase
	GCPMetadataURLBase string = "/computeMetadata/v1/?recursive=true"
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
	client.SetTimeout(time.Duration(conf.DefaultHttpRequestTimeout) * time.Millisecond)
	client.SetHeader("Metadata-Flavor", "Google")

	resp, err := client.R().Get("http://" + GCPIMDSRESTEndpoint + GCPMetadataURLBase)
	if err != nil && resp.StatusCode() != 200 {
		return err
	}

	json.Unmarshal(resp.Body(), &g.meta)
	return nil
}

func (g *GCP) ParseIpv4GatewayFromMetadataByMac(mac string) (string, error) {
	for i := 0; i < len(g.meta.Instance.Networkinterfaces); i++ {
		if mac == g.meta.Instance.Networkinterfaces[i].Mac {
			return g.meta.Instance.Networkinterfaces[i].Gateway, nil
		}
	}

	return "", errors.New("not found")
}

func (g *GCP) ParseLinkMTUFromMetadataByMac(mac string) (int, error) {
	for i := 0; i < len(g.meta.Instance.Networkinterfaces); i++ {
		if mac == g.meta.Instance.Networkinterfaces[i].Mac {
			return g.meta.Instance.Networkinterfaces[i].Mtu, nil
		}
	}

	return 0, errors.New("not found")
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

func (g *GCP) ConfigureNetworkFromCloudMeta(m *Environment) error {
	for i := 0; i < len(g.meta.Instance.Networkinterfaces); i++ {
		l, ok := m.links.LinksByMAC[g.meta.Instance.Networkinterfaces[i].Mac]
		if !ok {
			log.Errorf("Failed to find link having MAC Address='%+v'", g.meta.Instance.Networkinterfaces[i].Mac)
			continue
		}

		newAddresses, err := g.parseIpv4AddressesFromMetadataByMac(g.meta.Instance.Networkinterfaces[i].Mac)
		if err != nil {
			log.Errorf("Failed to parse Ip addresses of link='%+v' ifindex='%+v' from metadata: %+v", l.Name, l.Ifindex, err)
			continue
		}

		m.configureNetwork(&l, newAddresses)
	}

	return nil
}

func (g *GCP) SaveCloudMetadata() error {
	if err := system.CreateAndSaveJSON(conf.SystemState, g.meta); err != nil {
		return err
	}

	return nil
}

func (g *GCP) LinkSaveCloudMetadata(m *Environment) error {
	for i := 0; i < len(g.meta.Instance.Networkinterfaces); i++ {
		l, b := m.links.LinksByMAC[g.meta.Instance.Networkinterfaces[i].Mac]
		if !b {
			continue
		}

		link := g.meta.Instance.Networkinterfaces[i]
		if err := system.CreateAndSaveJSON(path.Join(conf.LinkStateDir, strconv.Itoa(l.Ifindex)), link); err != nil {
			return err
		}
	}

	return nil
}

func (e *Environment) routerGetGCP(rw http.ResponseWriter, r *http.Request) {
	web.JSONResponse(e.gcp.meta, rw)
}

func RegisterRouterGCP(r *mux.Router, e *Environment) {
	r.HandleFunc("/network", e.routerGetGCP).Methods("GET")
	r.HandleFunc("/system", e.routerGetGCP).Methods("GET")
}
