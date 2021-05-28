// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"encoding/json"
	"net/http"
	"path"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-resty/resty/v2"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/cloud-network-setup/pkg/network"
	"github.com/cloud-network-setup/pkg/utils"
)

const (
	// AzureIMDSRESTEndpoint Metadata endpoint.
	AzureIMDSRESTEndpoint string = "169.254.169.254"

	// AzureAPIVersion API version
	AzureAPIVersion string = "?api-version=2020-09-01"

	//AzureMetadtaURLBase URL base
	AzureMetadtaURLBase string = "/metadata/instance"
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

	routeTable            int
	addressesByMAC        map[string][]string
	routingRulesByAddress map[string]*network.IPRoutingRule
}

func NewAzure() *Azure {
	return &Azure{
		routeTable:            network.ROUTING_TABLE_MAX,
		addressesByMAC:        make(map[string][]string),
		routingRulesByAddress: make(map[string]*network.IPRoutingRule),
	}
}

func (az *Azure) FetchCloudMetadata() error {
	client := resty.New()
	client.SetHeader("Metadata", "True")

	resp, err := client.R().Get("http://" + AzureIMDSRESTEndpoint + AzureMetadtaURLBase + AzureAPIVersion)
	if resp.StatusCode() != 200 {
		log.Errorf("Failed to fetch metadata from Azure Instance Metadata Service: '%+v'", resp.StatusCode())
		return err
	}

	if err = json.Unmarshal(resp.Body(), &az.meta); err != nil {
		return err
	}

	return nil
}

func (az *Azure) parseIpv4AddressesFromMetadataByMac(mac string) (map[string]bool, error) {
	a := make(map[string]bool)

	for i := 0; i < len(az.meta.Network.Interface); i++ {
		if strings.ToLower(utils.FormatTextToMAC(az.meta.Network.Interface[i].MacAddress)) != mac {
			continue
		}

		subnet := az.meta.Network.Interface[i].Ipv4.Subnet[0]
		_, err := strconv.ParseInt(subnet.Prefix, 10, 32)
		if err != nil {
			log.Errorf("Failed to parse address prefix=%+v': %+v", subnet.Prefix, err)
			continue
		}

		for j := 0; j < len(az.meta.Network.Interface[i].Ipv4.IPAddress); j++ {
			privateIp := az.meta.Network.Interface[i].Ipv4.IPAddress[j].PrivateIpAddress + "/" + subnet.Prefix
			a[privateIp] = true
		}
		break
	}

	return a, nil
}

func (az *Azure) ConfigureCloudMetadataAddress() error {
	links, err := network.AcquireLinks()
	if err != nil {
		return err
	}

	for i := 0; i < len(az.meta.Network.Interface); i++ {
		mac := strings.ToLower(utils.FormatTextToMAC(az.meta.Network.Interface[i].MacAddress))

		l, ok := links.LinksByMAC[mac]
		if !ok {
			log.Errorf("Failed to find link having MAC Address='%+v': %+v", mac, err)
			continue
		}

		existingAddresses, err := network.GetIPv4Addreses(l.Name)
		if err != nil {
			log.Errorf("Failed to fetch Ip addresses of link='%+v' ifindex='%+v': %+v", l.Name, l.Ifindex, err)
			continue
		}

		newAddresses, err := az.parseIpv4AddressesFromMetadataByMac(mac)
		if err != nil {
			log.Errorf("Failed to fetch Ip addresses of link='%+v' ifindex='%+v' from metadata: %+v", l.Name, l.Ifindex, err)
			continue
		}

		if len(az.addressesByMAC[mac]) > 0 {
			earlierAddresses := az.addressesByMAC[mac]

			eq := reflect.DeepEqual(newAddresses, earlierAddresses)
			if eq {
				log.Debugf("Old metadata addresses='%+v' and new addresses='%+v' received from Azure IMDS endpoint are equal. Skipping ...",
					existingAddresses, newAddresses)
				continue
			}

			// Purge old addresses
			for _, i := range earlierAddresses {
				_, ok = newAddresses[i]
				if !ok {
					err = network.RemoveIPAddress(l.Name, i)
					if err != nil {
						log.Errorf("Failed to remove address='%+v' from link='%+v': '%+v'", i, l.Name, l.Ifindex, err)
						continue
					} else {
						log.Infof("Successfully removed address='%+v on link='%+v' ifindex='%d'", i, l.Name, l.Ifindex)

						r, ok := az.routingRulesByAddress[i]
						if ok {
							az.removeRoutingPolicyRule(r, &l)
							delete(az.routingRulesByAddress, i)
						}
					}
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

				// https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-multiple-ip-addresses-portal#add
				// echo 150 custom >> /etc/iproute2/rt_tables
				// ip rule add from 10.0.0.5 lookup custom
				// ip route add default via 10.0.0.1 dev eth2 table custom

				table := az.routeTable
				err = az.configureRoutingPolicyRule(&l, i)
				if err != nil {
					continue
				}

				az.configureRoute(table, &l)
			}
		}

		delete(az.addressesByMAC, mac)

		var a []string
		for i := range newAddresses {
			a = append(a, i)
		}
		az.addressesByMAC[mac] = a
	}

	return nil
}

func (az *Azure) configureRoutingPolicyRule(link *network.Link, address string) error {
	s := strings.SplitAfter(address, "/")
	a := strings.TrimSuffix(s[0], "/")

	rule := &network.IPRoutingRule{
		Address: a,
		Table:   az.routeTable,
	}

	err := network.AddRoutingPolicyRule(rule)
	if err != nil {
		log.Errorf("Failed to add routing policy rule for link='%+v' ifindex='%+v': '%+v'", link.Name, link.Ifindex, err)
	}

	log.Debugf("Successfully added routing policy rule for link='%+v' ifindex='%+v'", link.Name, link.Ifindex)

	az.routeTable--
	az.routingRulesByAddress[address] = rule

	return nil
}

func (az *Azure) removeRoutingPolicyRule(rule *network.IPRoutingRule, link *network.Link) error {
	err := network.RemoveRoutingPolicyRule(rule)
	if err != nil {
		log.Errorf("Failed to add routing policy rule for link='%+v' ifindex='%+v': '%+v'", link.Name, link.Ifindex, err)
	}

	log.Debugf("Successfully removed routing policy rule for link='%+v' ifindex='%+v'", link.Name, link.Ifindex)

	az.routingRulesByAddress[rule.Address] = rule

	az.routeTable--
	if az.routeTable == network.ROUTING_TABLE_MIN {
		az.routeTable = network.ROUTING_TABLE_MAX
	}

	return nil
}

func (az *Azure) configureRoute(table int, link *network.Link) error {
	if network.IsDefaultIpv4GatewayByLinkPresent(link.Ifindex) {
		return nil
	}

	gw, err := network.GetDefaultIpv4Gateway()
	if err != nil {
		log.Errorf("Failed to determine default gateway: '%+v'", err)
		return err
	}

	err = network.AddRoute(link.Ifindex, table, gw)
	if err != nil {
		log.Errorf("Failed to added default gateway='%+v' for link='%+v' ifindex='%+v': '%+v'", gw, link.Name, link.Ifindex, err)
	}

	log.Debugf("Successfully added default gateway='%+v' for link='%+v' ifindex='%+v'", gw, link.Name, link.Ifindex)

	return nil
}

func (az *Azure) SaveCloudMetadata() error {
	if err := utils.CreateAndSaveJSON("/run/cloud-network-setup/system", az.meta); err != nil {
		log.Errorf("Failed to write to system file: %+v", err)
		return err
	}

	return nil
}

func (az *Azure) LinkSaveCloudMetadata() error {
	links, err := network.AcquireLinks()
	if err != nil {
		return err
	}

	for i := 0; i < len(az.meta.Network.Interface); i++ {
		mac := strings.ToLower(utils.FormatTextToMAC(az.meta.Network.Interface[i].MacAddress))
		l, b := links.LinksByMAC[mac]
		if !b {
			continue
		}

		link := az.meta.Network.Interface[i]
		err = utils.CreateAndSaveJSON(path.Join("/run/cloud-network-setup/links", strconv.Itoa(l.Ifindex)), link)
		if err != nil {
			log.Errorf("Failed to write link state file link='%+v': %+v", l.Name, err)
			return err
		}
	}

	return nil
}

func (e *Enviroment) routerGetCompute(rw http.ResponseWriter, r *http.Request) {
	utils.JSONResponse(e.az.meta, rw)
}

func RegisterRouterAzure(r *mux.Router, e *Enviroment) {
	r.HandleFunc("/network", e.routerGetCompute).Methods("GET")
	r.HandleFunc("/system", e.routerGetCompute).Methods("GET")
}
