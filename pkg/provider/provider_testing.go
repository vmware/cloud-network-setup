package provider

import (
	"encoding/json"
	"testing"

	"github.com/cloud-network-setup/pkg/network"
	log "github.com/sirupsen/logrus"
)

func (m *Azure) TestFetchCloudMetadata() error {
	s := `{
        "compute": {
          "azEnvironment": "AzurePublicCloud",
          "customData": "",
          "isHostCompatibilityLayerVm": "false",
          "licenseType": "",
          "location": "westus",
          "name": "azure-test-vm-02Feb2021-21.38.13",
          "offer": "",
          "osProfile": {
            "adminUsername": "michellew",
            "computerName": "azure-test-vm-02Feb2021-21.38.13"
          },
          "osType": "Linux",
          "placementGroupId": "",
          "plan": {
            "name": "",
            "product": "",
            "publisher": ""
          },
          "platformFaultDomain": "0",
          "platformUpdateDomain": "0",
          "provider": "Microsoft.Compute",
          "publicKeys": [
            {
              "keyData": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6wmP/RH2P2xphEp2wsgt5IIbeVOQMA5KkEnw8I5+sFxMgH+kjmlzdDFuBeLTsq/Y8lzxNR8wu68DsXt/AIekYl/SJbw0wS1opKiUK+mJ9hS2h/9tc71RJJS9fePxsnjYJvs86tEqj3jzAcOj6OPUfXkIJMSY5IjfYMhE/Y5BBA0rGEvhAdzAVRpLcL3uEeEz36LerWtj37geeG89B14X2T1ynWVn7gu5MBXXAv3AAKsYxWUcO/NrrG9SJtTinRvhiKUVd/dJcwI3bVGj19rCesJ8bcdFaOjKtVAJdXps2BxWLu0tiLhxHy/FgU8Ccid9rrKudGL0L2p0Ox2+PHK77 jenkins@photon-jenkins\n",
              "path": "/home/michellew/.ssh/authorized_keys"
            }
          ],
          "publisher": "",
          "resourceGroupName": "officialtestgosc",
          "resourceId": "/subscriptions/a7032fc9-f2b1-49d7-a6d3-c4c06f75df70/resourceGroups/officialtestgosc/providers/Microsoft.Compute/virtualMachines/azure-test-vm-02Feb2021-21.38.13",
          "securityProfile": {
            "secureBootEnabled": "false",
            "virtualTpmEnabled": "false"
          },
          "sku": "",
          "storageProfile": {
            "dataDisks": [],
            "imageReference": {
              "id": "",
              "offer": "",
              "publisher": "",
              "sku": "",
              "version": ""
            },
            "osDisk": {
              "caching": "ReadWrite",
              "createOption": "FromImage",
              "diffDiskSettings": {
                "option": ""
              },
              "diskSizeGB": "16",
              "encryptionSettings": {
                "enabled": "false"
              },
              "image": {
                "uri": "https://officialtestgosc.blob.core.windows.net/mydisks/azure-test-vm-02Feb2021-21.38.13.vhd"
              },
              "managedDisk": {
                "id": "",
                "storageAccountType": ""
              },
              "name": "osdisk_51e4a941a0",
              "osType": "Linux",
              "vhd": {
                "uri": "https://officialtestgosc.blob.core.windows.net/vhds/osdisk_51e4a941a0.vhd"
              },
              "writeAcceleratorEnabled": "false"
            }
          },
          "subscriptionId": "a7032fc9-f2b1-49d7-a6d3-c4c06f75df70",
          "tags": "",
          "tagsList": [],
          "version": "",
          "vmId": "485c64b1-ba68-4a3f-b6b2-80c4ab8cb227",
          "vmScaleSetName": "",
          "vmSize": "Standard_DS1_v2",
          "zone": ""
        },
        "network": {
          "interface": [
            {
              "ipv4": {
                "ipAddress": [
                  {
                    "privateIpAddress": "10.0.0.4",
                    "publicIpAddress": "104.42.20.194"
                  },
                  {
                    "privateIpAddress": "10.0.0.6",
                    "publicIpAddress": ""
                  },
                  {
                    "privateIpAddress": "10.0.0.7",
                    "publicIpAddress": ""
                  }
                ],
                "subnet": [
                  {
                    "address": "10.0.0.0",
                    "prefix": "24"
                  }
                ]
              },
              "ipv6": {
                "ipAddress": []
              },
              "macAddress": "000c295fd139"
            },
            {
              "ipv4": {
                "ipAddress": [
                  {
                    "privateIpAddress": "10.0.0.8",
                    "publicIpAddress": "13.64.224.132"
                  }
                ],
                "subnet": [
                  {
                    "address": "10.0.0.0",
                    "prefix": "24"
                  }
                ]
              },
              "ipv6": {
                "ipAddress": []
              },
              "macAddress": "4ec58828c1c0"
            }
          ]
        }
      }`

	if err := json.Unmarshal([]byte(s), &m.meta); err != nil {
		return err
	}

	return nil
}

func TestAzure(t *testing.T) {
	var err error

	m := New("azure")

	m.Links, err = network.AcquireLinks()
	if err != nil {
		log.Errorf("Failed to acquire link information: %+v", err)
		return nil
	}

	err = m.az.TestFetchCloudMetadata(
}
