// Copyright 2024 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"encoding/json"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/vmware/cloud-network-setup/pkg/parser"
	"github.com/vmware/cloud-network-setup/pkg/system"
	"github.com/vmware/cloud-network-setup/pkg/web"
	"github.com/vmware/cloud-network-setup/conf"
)

const (
	// Azure IMDS REST Endpoint.
	AzureIMDSRESTEndpoint string = "169.254.169.254"

	// Azure API Version API version
	AzureAPIVersion string = "?api-version=2020-09-01"

	// Azure Metadata URL base
	AzureMetadataURLBase string = "/metadata/instance"
)

// Azure compute metadata
type AzureMetaData struct {
	Compute struct {
		AzEnvironment              string `json:"azEnvironment,omitempty"`
		CustomData                 string `json:"customData,omitempty"`
		IsHostCompatibilityLayerVM string `json:"isHostCompatibilityLayerVm,omitempty"`
		LicenseType                string `json:"licenseType,omitempty"`
		Location                   string `json:"location,omitempty"`
		Name                       string `json:"name,omitempty"`
		Offer                      string `json:"offer,omitempty"`
		OsProfile                  struct {
			AdminUsername string `json:"adminUsername,omitempty"`
			ComputerName  string `json:"computerName,omitempty"`
		} `json:"osProfile"`
		OsType           string `json:"osType,omitempty"`
		PlacementGroupID string `json:"placementGroupId,omitempty"`
		Plan             struct {
			Name      string `json:"name,omitempty"`
			Product   string `json:"product,omitempty"`
			Publisher string `json:"publisher,omitempty"`
		} `json:"plan"`
		PlatformFaultDomain  string `json:"platformFaultDomain,omitempty"`
		PlatformUpdateDomain string `json:"platformUpdateDomain,omitempty"`
		Provider             string `json:"provider,omitempty"`
		PublicKeys           []struct {
			KeyData string `json:"keyData,omitempty"`
			Path    string `json:"path,omitempty"`
		} `json:"publicKeys"`
		Publisher         string `json:"publisher,omitempty"`
		ResourceGroupName string `json:"resourceGroupName,omitempty"`
		ResourceID        string `json:"resourceId,omitempty"`
		SecurityProfile   struct {
			SecureBootEnabled string `json:"secureBootEnabled,omitempty"`
			VirtualTpmEnabled string `json:"virtualTpmEnabled,omitempty"`
		} `json:"securityProfile"`

		StorageProfile struct {
			DataDisks      []interface{} `json:"dataDisks,omitempty"`
			ImageReference struct {
				ID        string `json:"id,omitempty"`
				Offer     string `json:"offer,omitempty"`
				Publisher string `json:"publisher,omitempty"`
				Sku       string `json:"sku,omitempty"`
				Version   string `json:"version,omitempty"`
			} `json:"imageReference"`
			OsDisk struct {
				Caching          string `json:"caching,omitempty,omitempty"`
				CreateOption     string `json:"createOption,omitempty,omitempty"`
				DiffDiskSettings struct {
					Option string `json:"option"`
				} `json:"diffDiskSettings"`
				DiskSizeGB         string `json:"diskSizeGB,omitempty"`
				EncryptionSettings struct {
					Enabled string `json:"enabled"`
				} `json:"encryptionSettings"`
				Image struct {
					URI string `json:"uri"`
				} `json:"image"`
				ManagedDisk struct {
					ID                 string `json:"id,omitempty"`
					StorageAccountType string `json:"storageAccountType,omitempty"`
				} `json:"managedDisk"`
				Name   string `json:"name,omitempty"`
				OsType string `json:"osType,omitempty"`
				Vhd    struct {
					URI string `json:"uri"`
				} `json:"vhd"`
				WriteAcceleratorEnabled string `json:"writeAcceleratorEnabled"`
			} `json:"osDisk"`
		} `json:"storageProfile"`
		SubscriptionID string        `json:"subscriptionId,omitempty"`
		Tags           string        `json:"tags,omitempty"`
		TagsList       []interface{} `json:"tagsList,omitempty"`
		Version        string        `json:"version,omitempty"`
		VMID           string        `json:"vmId,omitempty"`
		VMScaleSetName string        `json:"vmScaleSetName,omitempty"`
		VMSize         string        `json:"vmSize,omitempty"`
		Zone           string        `json:"zone,omitempty"`
	} `json:"compute"`
	Network struct {
		Interface []struct {
			Ipv4 struct {
				IPAddress []struct {
					PrivateIpAddress string `json:"privateIpAddress,omitempty"`
					PublicIpAddress  string `json:"publicIpAddress,omitempty"`
				} `json:"ipAddress"`
				Subnet []struct {
					Address string `json:"address,omitempty"`
					Prefix  string `json:"prefix,omitempty"`
				} `json:"subnet"`
			} `json:"ipv4"`
			Ipv6 struct {
				IPAddress []struct {
					PrivateIpAddress string `json:"privateIpAddress,omitempty"`
					PublicIpAddress  string `json:"publicIpAddress,omitempty"`
				} `json:"ipAddress"`
			} `json:"ipv6"`
			MacAddress string `json:"macAddress,omitempty"`
		} `json:"interface"`
	} `json:"network"`
}

type Azure struct {
	meta AzureMetaData
}

func NewAzure() *Azure {
	return &Azure{}
}

func (az *Azure) FetchCloudMetadata() error {
	headers := make(map[string]string)
	headers["Metadata"] = "True"

	body, err := web.Dispatch("http://"+AzureIMDSRESTEndpoint+AzureMetadataURLBase+AzureAPIVersion, headers)
	if err != nil {
		return err
	}

	if err = json.Unmarshal(body, &az.meta); err != nil {
		return err
	}

	return nil
}

func (az *Azure) parseIpv4AddressesFromMetadataByMac(mac string) (map[string]bool, error) {
	a := make(map[string]bool)

	for i := range az.meta.Network.Interface {
		if strings.ToLower(parser.ParseMAC(az.meta.Network.Interface[i].MacAddress)) != mac {
			continue
		}

		subnet := az.meta.Network.Interface[i].Ipv4.Subnet[0]
		_, err := strconv.ParseInt(subnet.Prefix, 10, 32)
		if err != nil {
			log.Errorf("Failed to parse address prefix='%s': %+v", subnet.Prefix, err)
			continue
		}

		for j := range az.meta.Network.Interface[i].Ipv4.IPAddress {
			privateIp := az.meta.Network.Interface[i].Ipv4.IPAddress[j].PrivateIpAddress + "/" + subnet.Prefix
			a[privateIp] = true
		}
		break
	}

	return a, nil
}

func (az *Azure) ConfigureNetworkFromCloudMeta(m *Environment) error {
	for i := range az.meta.Network.Interface {
		mac := strings.ToLower(parser.ParseMAC(az.meta.Network.Interface[i].MacAddress))

		l, ok := m.Links.LinksByMAC[mac]
		if !ok {
			log.Errorf("Failed to find link having MAC Address='%+v'", mac)
			continue
		}

		newAddresses, err := az.parseIpv4AddressesFromMetadataByMac(mac)
		if err != nil {
			log.Errorf("Failed to fetch Ip addresses of link='%+v' ifindex='%+v' from metadata: %+v", l.Name, l.Ifindex, err)
			continue
		}

		m.configureNetwork(&l, newAddresses)
	}

	return nil
}

func (az *Azure) SaveCloudMetadata() error {
	if err := system.CreateAndSaveJSON(conf.SystemState, az.meta); err != nil {
		return err
	}

	return nil
}

func (az *Azure) LinkSaveCloudMetadata(m *Environment) error {
	for i := range az.meta.Network.Interface {
		mac := strings.ToLower(parser.ParseMAC(az.meta.Network.Interface[i].MacAddress))
		l, b := m.Links.LinksByMAC[mac]
		if !b {
			continue
		}

		link := az.meta.Network.Interface[i]
		if err := system.CreateAndSaveJSON(path.Join(conf.LinkStateDir, strconv.Itoa(l.Ifindex)), link); err != nil {
			return err
		}
	}

	return nil
}

func (m *Environment) routerGetCompute(rw http.ResponseWriter, r *http.Request) {
	m.Mutex.Lock()
	defer m.Mutex.Unlock()

	web.JSONResponse(m.az.meta, rw)
}

func RegisterRouterAzure(r *mux.Router, m *Environment) {
	r.HandleFunc("/network", m.routerGetCompute).Methods("GET")
	r.HandleFunc("/system", m.routerGetCompute).Methods("GET")
}
