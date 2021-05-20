// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sort"

	cloudprovider "github.com/cloud-network-setup/pkg/cloudprovider"
	"github.com/cloud-network-setup/pkg/cloudprovider/azure"
	"github.com/cloud-network-setup/pkg/conf"
	"github.com/cloud-network-setup/pkg/network"
	"github.com/cloud-network-setup/pkg/utils"
	"github.com/go-resty/resty/v2"
	"github.com/powersj/whatsthis"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

func fetchCloudMetadata(url string) ([]byte, error) {
	client := resty.New()

	resp, err := client.R().Get(url)
	if resp.StatusCode() != 200 {
		fmt.Printf("Unexpected status code, expected instead: %s", resp.Error())
		return nil, err
	}

	return resp.Body(), nil
}

func displayAzureCloudNetworkMetadata(n *azure.Azure) {
	links, err := network.AcquireLinksFromKernel()
	if err != nil {
		return
	}

	for i := 0; i < len(n.Network.Interface); i++ {
		subnet := n.Network.Interface[i].Ipv4.Subnet[0]

		var privateIP string
		var publicIP string
		for j := 0; j < len(n.Network.Interface[i].Ipv4.IPAddress); j++ {
			privateIP += fmt.Sprintf("%s/%s ", n.Network.Interface[i].Ipv4.IPAddress[j].PrivateIPAddress, subnet.Prefix)
			publicIP += fmt.Sprintf("%s ", n.Network.Interface[i].Ipv4.IPAddress[j].PublicIPAddress)
		}

		l, _ := links.LinksByMAC[utils.FormatTextToMAC(n.Network.Interface[i].MacAddress)]

		fmt.Printf("            Name: %+v \n", l.Name)
		fmt.Printf("     MAC Address: %+v \n", utils.FormatTextToMAC(n.Network.Interface[i].MacAddress))
		fmt.Printf("       Public IP: %+v \n", publicIP)
		fmt.Printf("      Private IP: %+v \n", privateIP)
		fmt.Printf("          Subnet: %+v \n\n", subnet.Address)
	}
}

func fetchCloudNetworkMetadata() {
	resp, err := fetchCloudMetadata("http://" + conf.IPFlag + ":" + conf.PortFlag + "/api/cloud/network")
	if err != nil {
		return
	}

	provider, _ := whatsthis.Cloud()
	switch provider.Name {
	case cloudprovider.Azure:

		f := azure.Azure{}
		json.Unmarshal(resp, &f)

		displayAzureCloudNetworkMetadata(&f)
		break
	default:
		fmt.Printf("Falied to determine cloud enviroment: %s", provider)
		return
	}
}

func displayAzureCloudSystemMetadata(c *azure.Azure) {
	fmt.Printf("Azure Environment: %+v \n", c.Compute.AzEnvironment)
	fmt.Printf("         Location: %+v \n", c.Compute.Location)
	fmt.Printf("             Name: %+v \n", c.Compute.Name)
	fmt.Printf("          OS Type: %+v \n", c.Compute.OsType)
	fmt.Printf("            VM Id: %+v \n", c.Compute.VMID)
	fmt.Printf("  VM ScaleSetName: %+v \n", c.Compute.VMScaleSetName)
	fmt.Printf("          VM Size: %+v \n", c.Compute.VMSize)
	fmt.Printf("             Zone: %+v \n", c.Compute.Zone)
	fmt.Printf("         Provider: %+v \n", c.Compute.Provider)
	fmt.Printf("  Subscription Id: %+v \n", c.Compute.SubscriptionID)
	fmt.Printf("     Public Keys : %+v \n", c.Compute.PublicKeys)
	fmt.Printf("         Version : %+v \n", c.Compute.Version)
}

func fetchCloudSystemMetadata() {
	resp, err := fetchCloudMetadata("http://" + conf.IPFlag + ":" + conf.PortFlag + "/api/cloud/system")
	if err != nil {
		return
	}

	provider, err := whatsthis.Cloud()
	switch provider.Name {
	case cloudprovider.Azure:

		f := azure.Azure{}
		json.Unmarshal(resp, &f)

		displayAzureCloudSystemMetadata(&f)
		break
	default:
		fmt.Printf("Falied to determine cloud enviroment: '%+v'", err)
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
		Name:     "cpctl",
		Version:  "v0.1",
		HelpName: "Introspects cloud network metadata",
	}
	app.EnableBashCompletion = true
	app.Commands = []*cli.Command{
		{
			Name:    "status",
			Aliases: []string{"s"},
			Usage:   "Show status system cloud metadata",
			Action: func(c *cli.Context) error {
				switch c.Args().First() {
				case "system":
					fetchCloudSystemMetadata()
					break
				case "network":
					fetchCloudNetworkMetadata()
					break
				default:
					fetchCloudSystemMetadata()
					fetchCloudNetworkMetadata()
				}
				return nil
			},
		},
	}

	sort.Sort(cli.FlagsByName(app.Flags))
	sort.Sort(cli.CommandsByName(app.Commands))

	err := app.Run(os.Args)
	if err != nil {
		fmt.Printf("Failed to run cli: %v", err)
	}
}
