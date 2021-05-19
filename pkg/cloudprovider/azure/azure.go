// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"encoding/json"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/cloud-network-setup/pkg/cloud"
	"github.com/cloud-network-setup/pkg/network"
	"github.com/cloud-network-setup/pkg/utils"
	"github.com/go-resty/resty/v2"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
)

const (
	// AzureIMDSRESTEndpoint Metadata enndpoint.
	AzureIMDSRESTEndpoint string = "169.254.169.254"

	// AzureAPIVersion API version
	AzureAPIVersion string = "?api-version=2020-09-01"

	//AzureMetadtaURLBase URL base
	AzureMetadtaURLBase string = "/metadata/instance"
)

// Azure compute metadata
type Azure struct {
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
					PrivateIPAddress string `json:"privateIpAddress,omitempty"`
					PublicIPAddress  string `json:"publicIpAddress,omitempty"`
				} `json:"ipAddress"`
				Subnet []struct {
					Address string `json:"address,omitempty"`
					Prefix  string `json:"prefix,omitempty"`
				} `json:"subnet"`
			} `json:"ipv4"`
			Ipv6 struct {
				IPAddress []struct {
					PrivateIPAddress string `json:"privateIpAddress,omitempty"`
					PublicIPAddress  string `json:"publicIpAddress,omitempty"`
				} `json:"ipAddress"`
			} `json:"ipv6"`
			MacAddress string `json:"macAddress,omitempty"`
		} `json:"interface"`
	} `json:"network"`
}

// FetchAzureCloudMetadata - Fetch Azure cloud metadata
func FetchAzureCloudMetadata(m *cloud.CloudManager) error {
	client := resty.New()
	client.SetHeader("Metadata", "True")

	resp, err := client.R().Get("http://" + AzureIMDSRESTEndpoint + AzureMetadtaURLBase + AzureAPIVersion)
	if resp.StatusCode() != 200 {
		log.Errorf("Unexpected status code, expected %d, got %d instead", 200, resp.StatusCode())
		return err
	}

	d := Azure{}
	json.Unmarshal(resp.Body(), &d)

	m.MetaData = d

	return nil
}

// AddressConfigureCloudMetadata configures link address
func AddressConfigureCloudMetadata(m *cloud.CloudManager) error {
	d := m.MetaData.(Azure)

	links, err := network.AcquireLinksFromKernel()
	if err != nil {
		return err
	}

	for i := 0; i < len(d.Network.Interface); i++ {
		subnet := d.Network.Interface[i].Ipv4.Subnet[0]

		for j := 0; j < len(d.Network.Interface[i].Ipv4.IPAddress); j++ {
			mac := strings.ToLower(utils.FormatTextToMAC(d.Network.Interface[i].MacAddress))

			l, ok := links.LinksByMAC[mac]
			if !ok {
				continue
			}

			prefix, err := strconv.ParseInt(subnet.Prefix, 10, 32)
			privateIP := d.Network.Interface[i].Ipv4.IPAddress[j].PrivateIPAddress

			err = network.AddAddress(l.Ifindex, privateIP, int(prefix))
			if err != nil {
				log.Errorf("Failed to Add IP='%+v' to link='%+v'", privateIP, l.Name, err)
			}
		}
	}

	return nil
}

// SaveCloudMetadata Saves azure link's metadata to /run
func SaveCloudMetadata(m *cloud.CloudManager) error {
	f, err := os.Create("/run/cloud-network-setup/system")
	if err != nil {
		log.Errorf("Failed to create system file: ", err)
		return err
	}
	defer f.Close()

	k := m.MetaData.(Azure)

	d, _ := json.MarshalIndent(k, "", " ")
	f.Write(d)

	return nil
}

// LinkSaveCloudMetadata Saves azure link's metadata to /run
func LinkSaveCloudMetadata(m *cloud.CloudManager) error {
	d := m.MetaData.(Azure)

	links, err := network.AcquireLinksFromKernel()
	if err != nil {
		return err
	}

	for i := 0; i < len(d.Network.Interface); i++ {
		mac := strings.ToLower(utils.FormatTextToMAC(d.Network.Interface[i].MacAddress))
		l, b := links.LinksByMAC[mac]
		if !b {
			continue
		}

		s := strconv.Itoa(l.Ifindex)
		file := path.Join("/run/cloud-network-setup/links", s)
		f, err := os.Create(file)
		if err != nil {
			log.Errorf("Failed to create link file '%+v': ", file, err)
			return err
		}

		defer f.Close()

		link := d.Network.Interface[i]

		d, _ := json.MarshalIndent(link, "", " ")
		f.Write(d)
	}

	return nil
}

func routerGetCompute(rw http.ResponseWriter, r *http.Request) {
	m := cloud.GetConext().MetaData.(Azure)

	switch r.Method {
	case "GET":
		utils.JSONResponse(m, rw)
		break
	default:
	}
}

// RegisterRouterAzure Register Azure APIs with router
func RegisterRouterAzure(router *mux.Router) {
	router.HandleFunc("/network", routerGetCompute)
	router.HandleFunc("/system", routerGetCompute)
}
