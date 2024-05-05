// Copyright 2024 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/vmware/cloud-network-setup/conf"
	"github.com/vmware/cloud-network-setup/pkg/cloud"
	"github.com/vmware/cloud-network-setup/pkg/network"
	"github.com/vmware/cloud-network-setup/pkg/parser"
	"github.com/vmware/cloud-network-setup/pkg/web"
	"github.com/vmware/cloud-network-setup/provider"
)

func displayAzureCloudNetworkMetadata(links *network.Links, n *provider.AzureMetaData) error {
	for i := 0; i < len(n.Network.Interface); i++ {
		subnet := n.Network.Interface[i].Ipv4.Subnet[0]

		var privateIp string
		var publicIp string
		for j := 0; j < len(n.Network.Interface[i].Ipv4.IPAddress); j++ {
			privateIp += fmt.Sprintf("%s/%s ", n.Network.Interface[i].Ipv4.IPAddress[j].PrivateIpAddress, subnet.Prefix)
			publicIp += fmt.Sprintf("%s ", n.Network.Interface[i].Ipv4.IPAddress[j].PublicIpAddress)
		}

		l, ok := links.LinksByMAC[strings.ToLower(parser.ParseMAC(n.Network.Interface[i].MacAddress))]
		if !ok {
			continue
		}

		fmt.Printf("       Name: %+v \n", l.Name)
		fmt.Printf("MAC Address: %+v \n", strings.ToLower(parser.ParseMAC(n.Network.Interface[i].MacAddress)))
		fmt.Printf("  Public Ip: %+v \n", publicIp)
		fmt.Printf(" Private Ip: %+v \n", privateIp)
		fmt.Printf("     Subnet: %+v \n\n", subnet.Address)
	}

	return nil
}

func displayEC2CloudNetworkMetadata(l *network.Link, n *provider.EC2MAC) error {
	fmt.Printf("              Owner Id: %+v \n", n.OwnerID)
	fmt.Printf("                  Name: %+v \n", l.Name)
	fmt.Printf("           MAC Address: %+v \n", n.Mac)
	fmt.Printf("         Device Number: %+v \n", n.DeviceNumber)
	fmt.Printf("          Interface Id: %+v \n", n.InterfaceID)
	if len(n.PublicHostname) > 0 {
		fmt.Printf("       Public Hostname: %+v \n", n.PublicHostname)
	}
	fmt.Printf("       Local Host name: %+v \n", n.LocalHostname)
	fmt.Printf("           Local Ipv4S: %+v \n", n.LocalIpv4S)

	if len(n.PublicIpv4S) > 0 {
		fmt.Printf("          Public Ipv4S: %+v \n", n.PublicIpv4S)
	}

	fmt.Printf("             Subnet Id: %+v \n", n.SubnetID)
	fmt.Printf("Subnet Ipv4 Cidr Block: %+v \n", n.SubnetIpv4CidrBlock)

	if len(n.Ipv4Associations.Ipv4Association) > 0 {
		fmt.Printf("    Ipv4 Association: %+v \n\n", n.Ipv4Associations.Ipv4Association)
	}

	fmt.Printf("     Security Group Id: %+v \n", n.SecurityGroupIds)
	fmt.Printf("       Security Groups: %+v \n", n.SecurityGroups)

	fmt.Printf("                Vpc ID: %+v \n", n.VpcID)
	fmt.Printf("   Vpc Ipv4 Cidr Block: %+v \n", n.VpcIpv4CidrBlock)
	fmt.Printf("  Vpc Ipv4 Cidr Blocks: %+v \n\n", n.VpcIpv4CidrBlocks)

	return nil
}

func displayGCPCloudNetworkMetadata(links *network.Links, g *provider.GCPMetaData) error {
	for i := 0; i < len(g.Instance.Networkinterfaces); i++ {
		l, ok := links.LinksByMAC[g.Instance.Networkinterfaces[i].Mac]
		if !ok {
			continue
		}

		fmt.Printf("                      Name: %+v \n", l.Name)
		fmt.Printf("               MAC Address: %+v \n", g.Instance.Networkinterfaces[i].Mac)
		fmt.Printf("                       MTU: %+v \n", g.Instance.Networkinterfaces[i].Mtu)
		fmt.Printf("                Private Ip: %+v \n", g.Instance.Networkinterfaces[i].IP)

		if len(g.Instance.Networkinterfaces[i].Ipaliases) > 0 {
			fmt.Printf("                Ip aliases: %+v \n", strings.Join(g.Instance.Networkinterfaces[i].Ipaliases, " "))
		}

		fmt.Printf("               Subnet mask: %+v \n", g.Instance.Networkinterfaces[i].Subnetmask)
		fmt.Printf("                   Gateway: %+v \n", g.Instance.Networkinterfaces[i].Gateway)
		fmt.Printf("               DNS servers: %+v \n", strings.Join(g.Instance.Networkinterfaces[i].Dnsservers, " "))
		fmt.Printf("                   Network: %+v \n", g.Instance.Networkinterfaces[i].Network)

		if len(g.Instance.Networkinterfaces[i].Targetinstanceips) > 0 {
			fmt.Printf("       Target instance Ips: %+v \n", g.Instance.Networkinterfaces[i].Targetinstanceips)
		}

		for i := range g.Instance.Networkinterfaces[i].Accessconfigs {
			fmt.Printf("Access configs External Ip: %+v Type: %+v\n", g.Instance.Networkinterfaces[i].Accessconfigs[i].Externalip, g.Instance.Networkinterfaces[i].Accessconfigs[i].Type)
		}

		fmt.Println()
	}

	return nil
}

func fetchCloudNetworkMetadata(ip string, port string) error {
	resp, err := web.Dispatch("http://"+ip+":"+port+"/api/cloud/network", nil)
	if err != nil {
		fmt.Printf("Failed to fetch instance metadata: '%v'", err)
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

		displayAzureCloudNetworkMetadata(&links, &f)
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

		displayGCPCloudNetworkMetadata(&links, &f)
	default:
		fmt.Printf("Unsupported cloud environment")
	}

	return nil
}

func displayAzureCloudSystemMetadata(c *provider.AzureMetaData, provider string) {
	fmt.Printf("     Cloud provider: %+v \n", provider)
	fmt.Printf("  Azure Environment: %+v \n", c.Compute.AzEnvironment)
	fmt.Printf("           Location: %+v \n", c.Compute.Location)
	fmt.Printf("               Name: %+v \n", c.Compute.Name)
	fmt.Printf("            OS Type: %+v \n", c.Compute.OsType)
	fmt.Printf("              VM Id: %+v \n", c.Compute.VMID)
	if len(c.Compute.VMScaleSetName) > 0 {
		fmt.Printf("  VM Scale Set Name: %+v \n", c.Compute.VMScaleSetName)
	}
	fmt.Printf("            VM Size: %+v \n", c.Compute.VMSize)
	if len(c.Compute.Zone) > 0 {
		fmt.Printf("               Zone: %+v \n", c.Compute.Zone)
	}
	fmt.Printf("           Provider: %+v \n", c.Compute.Provider)
	fmt.Printf("    Subscription Id: %+v \n", c.Compute.SubscriptionID)
	if len(c.Compute.Publisher) > 0 {
		fmt.Printf("          Publisher: %+v \n", c.Compute.Publisher)
	}
	if len(c.Compute.Version) > 0 {
		fmt.Printf("            Version: %+v \n", c.Compute.Version)
	}
	if len(c.Compute.LicenseType) > 0 {
		fmt.Printf("        License Type: %+v \n", c.Compute.LicenseType)
	}
	fmt.Printf("      Computer Name: %+v \n", c.Compute.OsProfile.ComputerName)
	if len(c.Compute.SecurityProfile.SecureBootEnabled) > 0 {
		fmt.Printf("Secure Boot Enabled: %+v \n", c.Compute.SecurityProfile.SecureBootEnabled)
	}
	if len(c.Compute.SecurityProfile.VirtualTpmEnabled) > 0 {
		fmt.Printf("Virtual Tpm Enabled: %+v \n", c.Compute.SecurityProfile.VirtualTpmEnabled)
	}
	if len(c.Compute.TagsList) > 0 {
		fmt.Printf("         Tags List: %+v \n", c.Compute.TagsList)
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
		fmt.Printf("              Offer: %+v \n", c.Compute.Offer)
	}
	if len(c.Compute.StorageProfile.DataDisks) > 0 {
		fmt.Printf("      Storage Profile: %+v \n", c.Compute.StorageProfile.DataDisks)
	}
	fmt.Printf("    Admin User name: %+v \n", c.Compute.OsProfile.AdminUsername)
}

func displayEC2CloudSystemMetadata(c *provider.EC2System, provider string) {
	fmt.Printf("                Cloud provider: %+v \n", provider)
	fmt.Printf("                        Ami ID: %+v \n", c.AmiID)
	fmt.Printf("                      Location: %+v \n", c.AmiLaunchIndex)
	fmt.Printf("             Ami Manifest Path: %+v \n", c.AmiManifestPath)
	fmt.Printf("      Block Device Mapping Ami: %+v Root: %+v\n", c.BlockDeviceMapping.Ami, c.BlockDeviceMapping.Root)
	fmt.Printf("                     Host name: %+v \n", c.Hostname)
	fmt.Printf("              Public Host name: %+v \n", c.PublicHostname)
	fmt.Printf("               Local Host name: %+v \n", c.LocalHostname)
	fmt.Printf("               Instance Action: %+v \n", c.InstanceAction)
	fmt.Printf("                   Instance Id: %+v \n", c.InstanceID)
	fmt.Printf("           Instance Life Cycle: %+v \n", c.InstanceLifeCycle)
	fmt.Printf("                  InstanceType: %+v \n", c.InstanceType)
	fmt.Printf("   Placement Availability Zone: %+v \n", c.Placement.AvailabilityZone)
	fmt.Printf("Placement Availability Zone Id: %+v \n", c.Placement.AvailabilityZoneID)
	fmt.Printf("              Placement Region: %+v \n", c.Placement.Region)
	fmt.Printf("                       Profile: %+v \n", c.Profile)
	fmt.Printf("                   Mac Address: %+v \n", c.Mac)
	fmt.Printf("                    Local Ipv4: %+v \n", c.LocalIpv4)
	fmt.Printf("                   Public Ipv4: %+v \n", c.PublicIpv4)
	fmt.Printf("               Services Domain: %+v \n", c.Services.Domain)
	fmt.Printf("            Services Partition: %+v \n", c.Services.Partition)
}

func displayGCPCloudSystemMetadata(g *provider.GCPMetaData, provider string) {
	fmt.Printf("                            Cloud Provider: %+v \n", provider)
	fmt.Printf("                                        Id: %+v \n", g.Instance.ID)
	fmt.Printf("                                      Name: %+v \n", g.Instance.Name)
	fmt.Printf("                              Cpu platform: %+v \n", g.Instance.Cpuplatform)
	if len(g.Instance.Description) > 0 {
		fmt.Printf("                               Description: %+v \n", g.Instance.Description)
	}
	fmt.Printf("                                     Image: %+v \n", g.Instance.Image)
	fmt.Printf("                              Machine type: %+v \n", g.Instance.Machinetype)

	for i := range g.Instance.Disks {
		fmt.Printf("                          Disk Device name: %+v \n", g.Instance.Disks[i].Devicename)
		fmt.Printf("                                Disk Index: %+v \n", g.Instance.Disks[i].Index)
		fmt.Printf("                            Disk Interface: %+v \n", g.Instance.Disks[i].Interface)
		fmt.Printf("                                 Disk Mode: %+v \n", g.Instance.Disks[i].Mode)
		fmt.Printf("                                 Disk Type: %+v \n", g.Instance.Disks[i].Type)
	}

	fmt.Printf("                         Maintenance event: %+v \n", g.Instance.Maintenanceevent)
	fmt.Printf("  Instance ID Scheduling Automatic restart: %+v \n", g.Instance.Scheduling.Automaticrestart)
	fmt.Printf("Instance ID Scheduling On host maintenance: %+v \n", g.Instance.Scheduling.Onhostmaintenance)
	fmt.Printf("        Instance ID Scheduling Preemptible: %+v \n", g.Instance.Scheduling.Preemptible)
	fmt.Printf("          nstance Virtualclock Drift token: %+v \n", g.Instance.Virtualclock.Drifttoken)
	fmt.Printf("                                      Zone: %+v \n", g.Instance.Zone)
	fmt.Printf("                        Remaining cpu time: %+v \n", g.Instance.Remainingcputime)
}

func displayGCPCloudProjectMetadata(g *provider.GCPMetaData) {
	fmt.Printf("                              Project Id: %+v \n", g.Project.Projectid)
	fmt.Printf("                      Numeric Project Id: %+v \n", g.Project.Numericprojectid)
	fmt.Printf(" Instane Service Accounts Default Aliase: %+v \n", g.Instance.Serviceaccounts.Default.Aliases)
	fmt.Printf("  Instane Service Accounts Default Email: %+v \n", g.Instance.Serviceaccounts.Default.Email)
	fmt.Printf(" Instane Service Accounts Default Scopes: %+v \n", strings.Join(g.Instance.Serviceaccounts.Default.Scopes, " "))
	fmt.Printf("         Instane Service Accounts Aliase: %+v \n", g.Instance.Serviceaccounts.Three8191186391ComputeDeveloperGserviceaccountCom.Aliases)
	fmt.Printf("          Instane Service Accounts Email: %+v \n", g.Instance.Serviceaccounts.Three8191186391ComputeDeveloperGserviceaccountCom.Email)
	fmt.Printf("         Instane Service Accounts Scopes: %+v \n", strings.Join(g.Instance.Serviceaccounts.Three8191186391ComputeDeveloperGserviceaccountCom.Scopes, " "))
}

func fetchCloudSystemMetadata(ip string, port string) {
	resp, err := web.Dispatch("http://"+ip+":"+port+"/api/cloud/system", nil)
	if err != nil {
		fmt.Printf("Failed to fetch instance metadata: '%v'", err)
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
		fmt.Printf("Failed to detect cloud environment: '%+v'", err)
		return
	}
}

func displayAzureCloudSSHKeysFromMetadata(c *provider.AzureMetaData) {
	fmt.Printf("  AdminUsername: %+v \n", c.Compute.OsProfile.AdminUsername)

	for i := range c.Compute.PublicKeys {
		fmt.Printf("Public Key Path: %+v \n", c.Compute.PublicKeys[i].Path)
		fmt.Printf("Public Key Data: %+v \n\n", c.Compute.PublicKeys[i].KeyData)
	}
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

func fetchSSHKeysFromCloudMetadata(ip string, port string) {
	resp, err := web.Dispatch("http://"+ip+":"+port+"/api/cloud/system", nil)
	if err != nil {
		fmt.Printf("Failed to fetch instance metadata: '%v'", err)
		return
	}

	switch cloud.DetectCloud() {
	case cloud.Azure:
		f := provider.AzureMetaData{}
		json.Unmarshal(resp, &f)

		displayAzureCloudSSHKeysFromMetadata(&f)
	case cloud.AWS:
		c, err := web.Dispatch("http://"+ip+":"+port+"/api/cloud/credentials", nil)
		if err != nil {
			return
		}

		displayEC2CloudSSHKeysFromMetadata(resp, c)
	case cloud.GCP:
		f := provider.GCPMetaData{}
		json.Unmarshal(resp, &f)

		displayGCPCloudSSHKeysFromMetadata(&f)
	default:
		fmt.Printf("Failed to detect cloud environment: '%+v'", err)
		return
	}
}

func fetchGCPCloudProjectMetadata(ip string, port string) {
	resp, err := web.Dispatch("http://"+ip+":"+port+"/api/cloud/system", nil)
	if err != nil {
		return
	}

	f := provider.GCPMetaData{}
	json.Unmarshal(resp, &f)

	displayGCPCloudProjectMetadata(&f)
}

func displayIdentityCredentialsFromMetadata(c *provider.EC2Credentials) {
	fmt.Printf("    Access key Id: %+v\n", c.Accesskeyid)
	fmt.Printf("             Type: %+v\n", c.Type)
	fmt.Printf("       Expiration: %+v\n", c.Expiration)
	fmt.Printf("             Code: %+v\n", c.Code)
	fmt.Printf("Secret access key: %+v\n", c.Secretaccesskey)
	fmt.Printf("            Token: %+v\n", c.Token)
}

func fetchIdentityCredentialsFromCloudMetadata(ip string, port string) {
	resp, err := web.Dispatch("http://"+ip+":"+port+"/api/cloud/credentials", nil)
	if err != nil {
		fmt.Printf("Failed to fetch instance metadata: '%v'", err)
		return
	}
	var c provider.EC2Credentials

	json.Unmarshal(resp, &c)
	displayIdentityCredentialsFromMetadata(&c)
}

func displayDynamicInstanceIdentityDocument(c *provider.EC2Document) {
	fmt.Printf("             Account Id: %+v\n", c.Accountid)
	fmt.Printf("           Architecture: %+v\n", c.Architecture)
	fmt.Printf("      Availability Zone: %+v\n", c.Availabilityzone)

	if len(c.Billingproducts) > 0 {
		fmt.Printf("       Billing products: %+v\n", c.Billingproducts)
	}
	fmt.Printf("                Image Id: %+v\n", c.Imageid)
	fmt.Printf("             Instance Id: %+v\n", c.Instanceid)
	fmt.Printf("           Instance Type: %+v\n", c.Instancetype)
	if len(c.Kernelid) > 0 {
		fmt.Printf("              Kernel id: %+v\n", c.Kernelid)
	}
	if len(c.Marketplaceproductcodes) > 0 {
		fmt.Printf("Market place product codes: %+v\n", c.Marketplaceproductcodes)
	}
	fmt.Printf("           Pending time: %+v\n", c.Pendingtime)
	fmt.Printf("             Private Ip: %+v\n", c.Privateip)
	if len(c.Ramdiskid) > 0 {
		fmt.Printf("             Ramdisk Id: %+v\n", c.Ramdiskid)
	}
	fmt.Printf("                 Region: %+v\n", c.Region)
	fmt.Printf("                Version: %+v\n", c.Version)
}

func fetchDynamicInstanceIdentityFromCloudMetadata(s string, ip string, port string) {
	resp, err := web.Dispatch("http://"+ip+":"+port+"/api/cloud/dynamicinstanceidentity/"+s, nil)
	if err != nil {
		fmt.Printf("Failed to fetch instance metadata: '%v'", err)
		return
	}
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
	}
}

func main() {
	conf, _ := conf.Parse()
	log.SetOutput(ioutil.Discard)

	ip, port, err := parser.ParseIpPort(conf.Network.Listen)
	if err != nil {
		fmt.Printf("Failed to parse Listen=%v : %v", conf.Network.Listen, err)
		os.Exit(1)
	}

	kind := cloud.DetectCloud()
	if len(kind) <= 0 {
		fmt.Println("Failed to detect cloud environment, Aborting ...")
		os.Exit(1)
	}

	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Printf("Version=%s\n", c.App.Version)
	}

	app := &cli.App{
		Name:    "cnctl",
		Version: "v0.1",
		Usage:   "Introspects cloud network metadata",
	}

	app.EnableBashCompletion = true
	app.Commands = []*cli.Command{
		{
			Name:    "status",
			Aliases: []string{"s"},
			Usage:   "Display cloud system or network status",
			Subcommands: []*cli.Command{
				{
					Name:  "system",
					Usage: "Display cloud system metadata",
					Action: func(c *cli.Context) error {
						fetchCloudSystemMetadata(ip, port)
						return nil
					},
				},
				{
					Name:  "network",
					Usage: "Display cloud network metadata",
					Action: func(c *cli.Context) error {
						fetchCloudNetworkMetadata(ip, port)
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
					Usage:   "Display SSH key",
					Action: func(c *cli.Context) error {
						fetchSSHKeysFromCloudMetadata(ip, port)
						return nil
					},
				},
				{
					Name:    "credentials",
					Aliases: []string{"c"},
					Usage:   "Display EC2 data identity credentials",
					Action: func(c *cli.Context) error {
						fetchIdentityCredentialsFromCloudMetadata(ip, port)
						return nil
					},
				},
				{
					Name:    "document",
					Aliases: []string{"d"},
					Usage:   "Display EC2 data identity credentials document",
					Action: func(c *cli.Context) error {
						fetchDynamicInstanceIdentityFromCloudMetadata("document", ip, port)
						return nil
					},
				},
				{
					Name:    "pkcs7",
					Aliases: []string{"p"},
					Usage:   "Display EC2 data identity credentials pkcs7",
					Action: func(c *cli.Context) error {
						fetchDynamicInstanceIdentityFromCloudMetadata("pkcs7", ip, port)
						return nil
					},
				},
				{
					Name:    "signature",
					Aliases: []string{"s"},
					Usage:   "Display EC2 data identity credentials signature",
					Action: func(c *cli.Context) error {
						fetchDynamicInstanceIdentityFromCloudMetadata("signature", ip, port)
						return nil
					},
				},
				{
					Name:    "rsa2048",
					Aliases: []string{"r"},
					Usage:   "Display EC2 data identity credentials rsa2048",
					Action: func(c *cli.Context) error {
						fetchDynamicInstanceIdentityFromCloudMetadata("rsa2048", ip, port)
						return nil
					},
				},
				{
					Name:    "project",
					Aliases: []string{"p"},
					Usage:   "Display GCP project metadata",
					Action: func(c *cli.Context) error {
						fetchGCPCloudProjectMetadata(ip, port)
						return nil
					},
				},
			},
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	if err := app.Run(os.Args); err != nil {
		fmt.Printf("Failed to run cli: '%+v'", err)
	}
}
