// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"

	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/cloud-network-setup/pkg/cloud"
	"github.com/cloud-network-setup/pkg/conf"
	"github.com/cloud-network-setup/pkg/network"
	"github.com/cloud-network-setup/pkg/provider"
	"github.com/cloud-network-setup/pkg/utils"
)

func fetchCloudMetadata(url string) ([]byte, error) {
	client := resty.New()

	resp, err := client.R().Get(url)
	if resp.StatusCode() != 200 {
		fmt.Printf("Failed to fetch metadata: '%v'", resp.Error())
		return nil, err
	}

	return resp.Body(), nil
}

func displayAzureCloudNetworkMetadata(links *network.Links, n *provider.AzureMetaData) error {
	for i := 0; i < len(n.Network.Interface); i++ {
		subnet := n.Network.Interface[i].Ipv4.Subnet[0]

		var privateIp string
		var publicIp string
		for j := 0; j < len(n.Network.Interface[i].Ipv4.IPAddress); j++ {
			privateIp += fmt.Sprintf("%s/%s ", n.Network.Interface[i].Ipv4.IPAddress[j].PrivateIpAddress, subnet.Prefix)
			publicIp += fmt.Sprintf("%s ", n.Network.Interface[i].Ipv4.IPAddress[j].PublicIpAddress)
		}

		l, ok := links.LinksByMAC[strings.ToLower(utils.FormatTextToMAC(n.Network.Interface[i].MacAddress))]
		if !ok {
			continue
		}

		fmt.Printf("             Name: %+v \n", l.Name)
		fmt.Printf("      MAC Address: %+v \n", strings.ToLower(utils.FormatTextToMAC(n.Network.Interface[i].MacAddress)))
		fmt.Printf("        Public IP: %+v \n", publicIp)
		fmt.Printf("       Private IP: %+v \n", privateIp)
		fmt.Printf("           Subnet: %+v \n\n", subnet.Address)
	}

	return nil
}

func displayEC2CloudNetworkMetadata(l *network.Link, n *provider.EC2MAC) error {
	fmt.Printf("            OwnerID: %+v \n", n.OwnerID)
	fmt.Printf("               Name: %+v \n", l.Name)
	fmt.Printf("        MAC Address: %+v \n", n.Mac)
	fmt.Printf("      Device Number: %+v \n", n.DeviceNumber)
	fmt.Printf("       Interface ID: %+v \n", n.InterfaceID)
	if len(n.PublicHostname) > 0 {
		fmt.Printf("     PublicHostname: %+v \n", n.PublicHostname)
	}
	fmt.Printf("     Local Hostname: %+v \n", n.LocalHostname)
	fmt.Printf("        Local Ipv4S: %+v \n", n.LocalIpv4S)

	if len(n.PublicIpv4S) > 0 {
		fmt.Printf("        PublicIpv4S: %+v \n", n.PublicIpv4S)
	}

	fmt.Printf("           SubnetID: %+v \n", n.SubnetID)
	fmt.Printf("SubnetIpv4CidrBlock: %+v \n", n.SubnetIpv4CidrBlock)

	if len(n.Ipv4Associations.Ipv4Association) > 0 {
		fmt.Printf("    Ipv4Association: %+v \n\n", n.Ipv4Associations.Ipv4Association)
	}

	fmt.Printf("    SecurityGroupId: %+v \n", n.SecurityGroupIds)
	fmt.Printf("     SecurityGroups: %+v \n", n.SecurityGroups)

	fmt.Printf("              VpcID: %+v \n", n.VpcID)
	fmt.Printf("   VpcIpv4CidrBlock: %+v \n", n.VpcIpv4CidrBlock)
	fmt.Printf("  VpcIpv4CidrBlocks: %+v \n\n", n.VpcIpv4CidrBlocks)

	return nil
}

func displayGCPCloudNetworkMetadata(links *network.Links, g *provider.GCPMetaData) error {
	for i := 0; i < len(g.Instance.Networkinterfaces); i++ {
		l, ok := links.LinksByMAC[g.Instance.Networkinterfaces[i].Mac]
		if !ok {
			continue
		}

		fmt.Printf("                    Name: %+v \n", l.Name)
		fmt.Printf("             MAC Address: %+v \n", g.Instance.Networkinterfaces[i].Mac)
		fmt.Printf("                     MTU: %+v \n", g.Instance.Networkinterfaces[i].Mtu)
		fmt.Printf("              Private IP: %+v \n", g.Instance.Networkinterfaces[i].IP)

		if len(g.Instance.Networkinterfaces[i].Ipaliases) > 0 {
			fmt.Printf("               Ipaliases: %+v \n", strings.Join(g.Instance.Networkinterfaces[i].Ipaliases, " "))
		}

		fmt.Printf("              Subnetmask: %+v \n", g.Instance.Networkinterfaces[i].Subnetmask)
		fmt.Printf("                 Gateway: %+v \n", g.Instance.Networkinterfaces[i].Gateway)
		fmt.Printf("              Dnsservers: %+v \n", strings.Join(g.Instance.Networkinterfaces[i].Dnsservers, " "))
		fmt.Printf("                 Network: %+v \n", g.Instance.Networkinterfaces[i].Network)

		if len(g.Instance.Networkinterfaces[i].Targetinstanceips) > 0 {
			fmt.Printf("       Targetinstanceips: %+v \n", g.Instance.Networkinterfaces[i].Targetinstanceips)
		}

		for i := range g.Instance.Networkinterfaces[i].Accessconfigs {
			fmt.Printf("Accessconfigs Externalip: %+v Type: %+v\n", g.Instance.Networkinterfaces[i].Accessconfigs[i].Externalip, g.Instance.Networkinterfaces[i].Accessconfigs[i].Type)
		}

		fmt.Println()
	}

	return nil
}

func fetchCloudNetworkMetadata() error {
	resp, err := fetchCloudMetadata("http://" + conf.IPFlag + ":" + conf.PortFlag + "/api/cloud/network")
	if err != nil {
		fmt.Printf("Failed to fetch instance metadata: '%+v'", err)
		return err
	}

	links, err := network.AcquireLinks()
	if err != nil {
		return err
	}

	switch cloud.DetectCloud() {
	case cloud.Azure:
		f := provider.AzureMetaData{}
		json.Unmarshal(resp, &f)

		displayAzureCloudNetworkMetadata(links, &f)
	case cloud.AWS:
		m := make(map[string]interface{})
		json.Unmarshal(resp, &m)

		for _, v := range m {
			s, _ := json.Marshal(v)

			t := provider.EC2MAC{}
			json.Unmarshal(s, &t)

			l, ok := links.LinksByMAC[t.Mac]
			if !ok {
				continue
			}

			displayEC2CloudNetworkMetadata(&l, &t)
		}
	case cloud.GCP:
		f := provider.GCPMetaData{}
		json.Unmarshal(resp, &f)

		displayGCPCloudNetworkMetadata(links, &f)
	default:
		fmt.Printf("Unsupported cloud enviroment")
	}

	return nil
}

func displayAzureCloudSystemMetadata(c *provider.AzureMetaData, provider string) {
	fmt.Printf("   Cloud provider: %+v \n", provider)
	fmt.Printf("Azure Environment: %+v \n", c.Compute.AzEnvironment)
	fmt.Printf("         Location: %+v \n", c.Compute.Location)
	fmt.Printf("             Name: %+v \n", c.Compute.Name)
	fmt.Printf("          OS Type: %+v \n", c.Compute.OsType)
	fmt.Printf("            VM Id: %+v \n", c.Compute.VMID)
	if len(c.Compute.VMScaleSetName) > 0 {
		fmt.Printf("  VM ScaleSetName: %+v \n", c.Compute.VMScaleSetName)
	}
	fmt.Printf("          VM Size: %+v \n", c.Compute.VMSize)
	if len(c.Compute.Zone) > 0 {
		fmt.Printf("             Zone: %+v \n", c.Compute.Zone)
	}
	fmt.Printf("         Provider: %+v \n", c.Compute.Provider)
	fmt.Printf("  Subscription Id: %+v \n", c.Compute.SubscriptionID)
	if len(c.Compute.Publisher) > 0 {
		fmt.Printf("        Publisher: %+v \n", c.Compute.Publisher)
	}
	if len(c.Compute.Version) > 0 {
		fmt.Printf("         Version : %+v \n", c.Compute.Version)
	}
	if len(c.Compute.LicenseType) > 0 {
		fmt.Printf("     LicenseType : %+v \n", c.Compute.LicenseType)
	}
	fmt.Printf("     ComputerName: %+v \n", c.Compute.OsProfile.ComputerName)
	if len(c.Compute.SecurityProfile.SecureBootEnabled) > 0 {
		fmt.Printf("SecureBootEnabled: %+v \n", c.Compute.SecurityProfile.SecureBootEnabled)
	}
	if len(c.Compute.SecurityProfile.VirtualTpmEnabled) > 0 {
		fmt.Printf("VirtualTpmEnabled: %+v \n", c.Compute.SecurityProfile.VirtualTpmEnabled)
	}
	if len(c.Compute.TagsList) > 0 {
		fmt.Printf("         TagsList: %+v \n", c.Compute.TagsList)
	}
	if len(c.Compute.Plan.Name) > 0 {
		fmt.Printf("        Plan Name: %+v \n", c.Compute.Plan.Name)
	}
	if len(c.Compute.Plan.Name) > 0 {
		fmt.Printf("     Plan Product: %+v \n", c.Compute.Plan.Product)
	}
	if len(c.Compute.Plan.Publisher) > 0 {
		fmt.Printf("   Plan Publisher: %+v \n", c.Compute.Plan.Publisher)
	}
	if len(c.Compute.Offer) > 0 {
		fmt.Printf("            Offer: %+v \n", c.Compute.Offer)
	}
	if len(c.Compute.StorageProfile.DataDisks) > 0 {
		fmt.Printf("       StorageProfile: %+v \n", c.Compute.StorageProfile.DataDisks)
	}
	fmt.Printf("    AdminUsername: %+v \n", c.Compute.OsProfile.AdminUsername)
}

func displayEC2CloudSystemMetadata(c *provider.EC2System, provider string) {
	fmt.Printf("    Cloud provider: %+v \n", provider)
	fmt.Printf("             AmiID: %+v \n", c.AmiID)
	fmt.Printf("          Location: %+v \n", c.AmiLaunchIndex)
	fmt.Printf("   AmiManifestPath: %+v \n", c.AmiManifestPath)
	fmt.Printf("BlockDeviceMapping: %+v \n", c.BlockDeviceMapping)
	fmt.Printf("          Hostname: %+v \n", c.Hostname)
	fmt.Printf("    PublicHostname: %+v \n", c.PublicHostname)
	fmt.Printf("     LocalHostname: %+v \n", c.LocalHostname)
	fmt.Printf("    InstanceAction: %+v \n", c.InstanceAction)
	fmt.Printf("        InstanceID: %+v \n", c.InstanceID)
	fmt.Printf(" InstanceLifeCycle: %+v \n", c.InstanceLifeCycle)
	fmt.Printf("      InstanceType: %+v \n", c.InstanceType)
	fmt.Printf("         Placement: %+v \n", c.Placement)
	fmt.Printf("           Profile: %+v \n", c.Profile)
	fmt.Printf("       Mac Address: %+v \n", c.Mac)
	fmt.Printf("         LocalIpv4: %+v \n", c.LocalIpv4)
	fmt.Printf("        PublicIpv4: %+v \n", c.PublicIpv4)
	fmt.Printf("   Services Domain: %+v \n", c.Services.Domain)
	fmt.Printf("Services Partition: %+v \n", c.Services.Partition)
}

func displayGCPCloudSystemMetadata(g *provider.GCPMetaData, provider string) {
	fmt.Printf("                         Cloud Provider: %+v \n", provider)
	fmt.Printf("                                     ID: %+v \n", g.Instance.ID)
	fmt.Printf("                                   Name: %+v \n", g.Instance.Name)
	fmt.Printf("                            Cpuplatform: %+v \n", g.Instance.Cpuplatform)
	if len(g.Instance.Description) > 0 {
		fmt.Printf("                            Description: %+v \n", g.Instance.Description)
	}
	fmt.Printf("                                  Image: %+v \n", g.Instance.Image)
	fmt.Printf("                            Machinetype: %+v \n", g.Instance.Machinetype)

	for i := range g.Instance.Disks {
		fmt.Printf("                        Disk Devicename: %+v \n", g.Instance.Disks[i].Devicename)
		fmt.Printf("                             Disk Index: %+v \n", g.Instance.Disks[i].Index)
		fmt.Printf("                         Disk Interface: %+v \n", g.Instance.Disks[i].Interface)
		fmt.Printf("                              Disk Mode: %+v \n", g.Instance.Disks[i].Mode)
		fmt.Printf("                              Disk Type: %+v \n", g.Instance.Disks[i].Type)
	}

	fmt.Printf("                       Maintenanceevent: %+v \n", g.Instance.Maintenanceevent)
	fmt.Printf(" InstanceID Scheduling Automaticrestart: %+v \n", g.Instance.Scheduling.Automaticrestart)
	fmt.Printf("InstanceID Scheduling Onhostmaintenance: %+v \n", g.Instance.Scheduling.Onhostmaintenance)
	fmt.Printf("      InstanceID Scheduling Preemptible: %+v \n", g.Instance.Scheduling.Preemptible)
	fmt.Printf("       Instance Virtualclock Drifttoken: %+v \n", g.Instance.Virtualclock.Drifttoken)
	fmt.Printf("                                   Zone: %+v \n", g.Instance.Zone)
	fmt.Printf("                       Remainingcputime: %+v \n", g.Instance.Remainingcputime)
	fmt.Printf("                              Projectid: %+v \n", g.Project.Projectid)
	fmt.Printf("                       Numericprojectid: %+v \n", g.Project.Numericprojectid)
	fmt.Printf(" Instane Serviceaccounts Default Aliase: %+v \n", g.Instance.Serviceaccounts.Default.Aliases)
	fmt.Printf("  Instane Serviceaccounts Default Email: %+v \n", g.Instance.Serviceaccounts.Default.Email)
	fmt.Printf(" Instane Serviceaccounts Default Scopes: %+v \n", strings.Join(g.Instance.Serviceaccounts.Default.Scopes, " "))
	fmt.Printf("         Instane Serviceaccounts Aliase: %+v \n", g.Instance.Serviceaccounts.Three8191186391ComputeDeveloperGserviceaccountCom.Aliases)
	fmt.Printf("          Instane Serviceaccounts Email: %+v \n", g.Instance.Serviceaccounts.Three8191186391ComputeDeveloperGserviceaccountCom.Email)
	fmt.Printf("         Instane Serviceaccounts Scopes: %+v \n", strings.Join(g.Instance.Serviceaccounts.Three8191186391ComputeDeveloperGserviceaccountCom.Scopes, " "))
}

func fetchCloudSystemMetadata() {
	resp, err := fetchCloudMetadata("http://" + conf.IPFlag + ":" + conf.PortFlag + "/api/cloud/system")
	if err != nil {
		return
	}

	e := cloud.DetectCloud()
	switch e {
	case cloud.Azure:
		f := provider.AzureMetaData{}
		json.Unmarshal(resp, &f)

		displayAzureCloudSystemMetadata(&f, e)
	case cloud.AWS:
		f := provider.EC2System{}
		json.Unmarshal(resp, &f)

		displayEC2CloudSystemMetadata(&f, e)
	case cloud.GCP:
		f := provider.GCPMetaData{}
		json.Unmarshal(resp, &f)

		displayGCPCloudSystemMetadata(&f, e)
	default:
		fmt.Printf("Failed to detect cloud enviroment: '%+v'", err)
		return
	}
}

func displayAzureCloudSSHKeysFromMetadata(c *provider.AzureMetaData) {
	fmt.Printf("AdminUsername: %+v \n", c.Compute.OsProfile.AdminUsername)
	fmt.Printf("  Public Keys: %+v \n\n", c.Compute.PublicKeys)
}

func displayEC2CloudSSHKeysFromMetadata(k []byte, c []byte) {
	m := make(map[string]interface{})
	json.Unmarshal(k, &m)

	for k, v := range m {
		if k == "public-keys" {
			keys := v.(map[string]interface{})
			for s, t := range keys {
				fmt.Printf("%+v: %+v\n\n", s, t)
			}
		}
	}
}

func displayGCPCloudSSHKeysFromMetadata(g *provider.GCPMetaData) {
	k := strings.Trim(g.Project.Attributes.SSHKeys, " ") + "\n" + strings.Trim(g.Project.Attributes.Sshkeys, " ")
	ssh := strings.Split(k, "\n")
	for _, s := range ssh {
		if len(s) > 0 {
			fmt.Printf("ssh-key: %v\n\n", s)
		}
	}
}

func fetchSSHKeysFromCloudMetadata() {
	resp, err := fetchCloudMetadata("http://" + conf.IPFlag + ":" + conf.PortFlag + "/api/cloud/system")
	if err != nil {
		return
	}

	switch cloud.DetectCloud() {
	case cloud.Azure:
		f := provider.AzureMetaData{}
		json.Unmarshal(resp, &f)

		displayAzureCloudSSHKeysFromMetadata(&f)
	case cloud.AWS:
		c, err := fetchCloudMetadata("http://" + conf.IPFlag + ":" + conf.PortFlag + "/api/cloud/credentials")
		if err != nil {
			return
		}

		displayEC2CloudSSHKeysFromMetadata(resp, c)
	case cloud.GCP:
		f := provider.GCPMetaData{}
		json.Unmarshal(resp, &f)

		displayGCPCloudSSHKeysFromMetadata(&f)
	default:
		fmt.Printf("Failed to detect cloud enviroment: '%+v'", err)
		return
	}
}

func displayIdentityCredentialsFromMetadata(c *provider.EC2Credentials) {
	fmt.Printf("    Accesskeyid: %+v\n", c.Accesskeyid)
	fmt.Printf("           Type: %+v\n", c.Type)
	fmt.Printf("     Expiration: %+v\n", c.Expiration)
	fmt.Printf("           Code: %+v\n", c.Code)
	fmt.Printf("Secretaccesskey: %+v\n", c.Secretaccesskey)
	fmt.Printf("          Token: %+v\n", c.Token)
}

func fetchIdentityCredentialsFromCloudMetadata() {
	resp, err := fetchCloudMetadata("http://" + conf.IPFlag + ":" + conf.PortFlag + "/api/cloud/credentials")
	if err != nil {
		return
	}

	switch cloud.DetectCloud() {
	case cloud.AWS:
		var c provider.EC2Credentials

		json.Unmarshal(resp, &c)
		displayIdentityCredentialsFromMetadata(&c)
	default:
		fmt.Printf("unsupported: '%+v'", err)
		return
	}
}

func displayDynamicInstanceIdentityDocument(c *provider.EC2Document) {
	fmt.Printf("              Accountid: %+v\n", c.Accountid)
	fmt.Printf("           Architecture: %+v\n", c.Architecture)
	fmt.Printf("       Availabilityzone: %+v\n", c.Availabilityzone)

	if len(c.Billingproducts) > 0 {
		fmt.Printf("        Billingproducts: %+v\n", c.Billingproducts)
	}
	fmt.Printf("                Imageid: %+v\n", c.Imageid)
	fmt.Printf("             Instanceid: %+v\n", c.Instanceid)
	fmt.Printf("           Instancetype: %+v\n", c.Instancetype)
	if len(c.Kernelid) > 0 {
		fmt.Printf("               Kernelid: %+v\n", c.Kernelid)
	}
	if len(c.Marketplaceproductcodes) > 0 {
		fmt.Printf("Marketplaceproductcodes: %+v\n", c.Marketplaceproductcodes)
	}
	fmt.Printf("            Pendingtime: %+v\n", c.Pendingtime)
	fmt.Printf("              Privateip: %+v\n", c.Privateip)
	if len(c.Ramdiskid) > 0 {
		fmt.Printf("              Ramdiskid: %+v\n", c.Ramdiskid)
	}
	fmt.Printf("                 Region: %+v\n", c.Region)
	fmt.Printf("                Version: %+v\n", c.Version)
}

func fetchDynamicInstanceIdentityFromCloudMetadata(s string) {
	resp, err := fetchCloudMetadata("http://" + conf.IPFlag + ":" + conf.PortFlag + "/api/cloud/dynamicinstanceidentity/" + s)
	if err != nil {
		return
	}

	switch cloud.DetectCloud() {
	case cloud.AWS:

		switch s {
		case "document":
			var c provider.EC2Document

			json.Unmarshal(resp, &c)
			displayDynamicInstanceIdentityDocument(&c)
		case "pkcs7":
			var c string

			json.Unmarshal(resp, &c)
			fmt.Println(c)
		case "signature":
			var c string

			json.Unmarshal(resp, &c)
			fmt.Println(c)
		case "rsa2048":
			var c string

			json.Unmarshal(resp, &c)
			fmt.Println(c)
		default:
		}
	default:
		fmt.Printf("unsupported: '%+v'", err)
		return
	}
}

func main() {
	conf.Parse()
	log.SetOutput(ioutil.Discard)

	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("version=%s\n", c.App.Version)
	}

	app := &cli.App{
		Name:     "cnctl",
		Version:  "v0.1",
		HelpName: "Introspects cloud network metadata",
	}

	app.EnableBashCompletion = true
	app.Commands = []*cli.Command{
		{
			Name:    "status",
			Aliases: []string{"s"},
			Usage:   "Display system or network status",
			Subcommands: []*cli.Command{
				{
					Name:  "system",
					Usage: "Display cloud system metadata",
					Action: func(c *cli.Context) error {
						fetchCloudSystemMetadata()
						return nil
					},
				},
				{
					Name:  "network",
					Usage: "Display cloud network metadata",
					Action: func(c *cli.Context) error {
						fetchCloudNetworkMetadata()
						return nil
					},
				},
			},
		},
		{
			Name:  "show",
			Usage: "Display credentials",
			Subcommands: []*cli.Command{
				{
					Name:    "ssh-keys",
					Aliases: []string{"k"},
					Usage:   "Display Display SSH key",
					Action: func(c *cli.Context) error {
						fetchSSHKeysFromCloudMetadata()
						return nil
					},
				},
				{
					Name:    "credentials",
					Aliases: []string{"c"},
					Usage:   "Display EC2 data identity credentials",
					Action: func(c *cli.Context) error {
						fetchIdentityCredentialsFromCloudMetadata()
						return nil
					},
				},
				{
					Name:    "document",
					Aliases: []string{"d"},
					Usage:   "Display EC2 data identity credentials document",
					Action: func(c *cli.Context) error {
						fetchDynamicInstanceIdentityFromCloudMetadata("document")
						return nil
					},
				},
				{
					Name:    "pkcs7",
					Aliases: []string{"p"},
					Usage:   "Display EC2 data identity credentials pkcs7",
					Action: func(c *cli.Context) error {
						fetchDynamicInstanceIdentityFromCloudMetadata("pkcs7")
						return nil
					},
				},
				{
					Name:    "signature",
					Aliases: []string{"s"},
					Usage:   "Display EC2 data identity credentials signature",
					Action: func(c *cli.Context) error {
						fetchDynamicInstanceIdentityFromCloudMetadata("signature")
						return nil
					},
				},
				{
					Name:    "rsa2048",
					Aliases: []string{"r"},
					Usage:   "Display EC2 data identity credentials rsa2048",
					Action: func(c *cli.Context) error {
						fetchDynamicInstanceIdentityFromCloudMetadata("rsa2048")
						return nil
					},
				},
			},
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	err := app.Run(os.Args)
	if err != nil {
		fmt.Printf("Failed to run cli: '%v'", err)
	}
}
