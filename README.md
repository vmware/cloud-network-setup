#### cloud-network
----

```cloud-network``` configures network in cloud environment. In cloud environment instances are set public IPs and private IPs. If more than one private Ip is configured then except the Ip which is provided by DHCP server others can't be fetched and configured. This project is adopting towards cloud network environment such as Azure, GCP, Amazon EC2. It fetches the metadata from the metadata server endpoint server, parses and then assign IPs and routes. When `cloud-network` is installed, it automatically configures network interfaces in cloud frameworks. Via netlink it detects which interfaces are available,  for all interfaces including the primary one, it looks up secondary IP addresses from the metadata and configures them on the interface.

A local RESTful JSON server runs on address `127.0.0.1:5209` and the instance metadata is saved in per link basis in the directory `/run/cloud-network`.

Interface configurations is checked periodically, and in case the configuration in the cloud framework changed, the interface will be reconfigured accordingly.

See

1. [Azure Instance Metadata Service ](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service?tabs=linux)
2. [EC2 Instance Metadata and user data](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
3. [GCP Instance Metadata](https://cloud.google.com/compute/docs/storing-retrieving-metadata)

 #### Use cases
----

 * How can I make my secondary network interface work in cloud instance ?

    This functionality is scattered across different scripts/tools that are cloud provider dependent. `cloud-network` provides a cloud agnostic mechanism to retrieve metadata like network parameters and configure the interfaces. That means no more manual editing the configuration and change it if configuration changes. `cloud-network` automatically configures the interfaces since it has the metadata information.
 
[Azure](https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-multiple-ip-addresses-portal#add)
```
# echo 150 custom >> /etc/iproute2/rt_tables
# ip rule add from 10.0.0.5 lookup custom
# ip route add default via 10.0.0.1 dev eth2 table custom
```

[AWS](https://aws.amazon.com/premiumsupport/knowledge-center/ec2-ubuntu-secondary-network-interface)
```
Gateway configuration
# ip route add default via 172.31.16.1 dev eth1 table 1000

Routes and rules
# ip route add 172.31.21.115 dev eth1 table 1000
# ip rule add from 172.31.21.115 lookup 1000
```

[GCP](https://cloud.google.com/vpc/docs/create-use-multiple-interfaces)

```
# sudo ifconfig eth1 192.168.0.2 netmask 255.255.255.255 broadcast 192.168.0.2 mtu 1430
# echo "1 rt1" | sudo tee -a /etc/iproute2/rt_tables
# sudo ip route add 192.168.0.1 src 192.168.0.2 dev eth1 table rt1
# sudo ip route add default via 192.168.0.1 dev eth1 table rt1
# sudo ip rule add from 192.168.0.2/32 table rt1
# sudo ip rule add to 192.168.0.2/32 table rt1
```
  

#### Building from source
----

By doing
```bash

❯ make build
❯ sudo make install
```

Due to security `cloud-network` runs in non root user `cloud-network`. It drops all privileges except `CAP_NET_ADMIN`.

```bash

❯  useradd -M -s /usr/bin/nologin cloud-network
```

#### Configuration
----

Configuration file `cloud-network.toml` located in `/etc/cloud-network/` directory to manage the configuration.

The `[System]` section takes following Keys:

`LogLevel=`

Specifies the log level. Takes one of `Trace`, `Debug`, `Info`, `Warning`, `Error`, `Fatal` and `Panic`. Defaults to `info`. See [sirupsen](https://github.com/sirupsen/logrus#level-logging)

`LogFormat=`

Specifies the log format. Takes one of text or json. Takes one of `text` or `json`, Defaults to `text`.

`RefreshTimer=`

Specifies the time interval, is the amount of time taken to retrieve the data from metadata endpoint.

The `[Network]` section takes following Keys:

`Listen=` 

Specifies the IP address and the port in the format `ip:port`, on which the local REST API server will listen. Defaults to `127.0.0.1:5209`.

`Supplementary=`

A whitespace-separated list of interfaces matching the device name. Specifies the interfaces you want to configure with a default gateway and routing policy rules for each IP address including the primary IP address. No default value is set for this key.

Note that when there are multiple interfaces, the secondary interface becomes unreachable. When `Supplementary=` is set, the default route and routing policy rules are automatically configured.

 ```bash
> cat /etc/cloud-network/cloud-network.toml
[System]
RefreshTimer="300s"
LogLevel="info"
LogFormat="text"

[Network]
Listen="127.0.0.1:5209"
Supplementary="eth0"
```

```bash
❯ > sudo systemctl status cloud-network
● cloud-network.service - Configures network in cloud enviroment
     Loaded: loaded (/usr/lib/systemd/system/cloud-network.service; disabled; vendor preset: enabled)
     Active: active (running) since Mon 2022-05-31 22:54:50 UTC; 3min 31s ago
   Main PID: 19754 (cloud-network)
      Tasks: 5 (limit: 4400)
     Memory: 8.7M
     CGroup: /system.slice/cloud-network.service
             └─19754 /usr/bin/cloud-network

May 31 22:54:50 zeus-final-2 systemd[1]: Started Configures network in cloud enviroment.


```

#### cnctl
----

`cnctl` is a CLI tool allows to view metadata, which is retirved from the endpoint metadata server.

```bash
❯ cnctl status system
    Cloud provider: aws
             AmiID: ami-005f15863xxxxxxxx
          Location: 0
BlockDeviceMapping: Ami:xvda Root:/dev/xvda
          Hostname: Zeus.us-west-2.compute.internal
    PublicHostname: Zeuspublic.us-west-2.compute.amazonaws.com
     LocalHostname: Zeus.us-west-2.compute.internal
    InstanceAction: none
        InstanceID: i-0c8c1test
 InstanceLifeCycle: on-demand
      InstanceType: t4g.micro
         Placement: AvailabilityZone:us-west-2d AvailabilityZoneID:usw2-az4 Region:us-west-2
           Profile: default-hvm
       Mac Address: 0e:c5:3f:c5:33:a5
         LocalIpv4: 192.31.63.114
        PublicIpv4: 02:42:8d:4c:0c:cf
   Services Domain: amazonaws.com
Services Partition: aws
```


```bash
❯ cnctl status network
            Name: eth0
     MAC Address: 00:0c:29:5f:d1:39
       Public IP: 104.42.20.194
      Private IP: 10.0.0.4/24 10.0.0.6/24 10.0.0.7/24
          Subnet: 10.0.0.0
```

#### Contributing
----

The **Cloud Network Setup** project team welcomes contributions from the community. If you wish to contribute code and you have not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).

slack channel [#photon](https://code.vmware.com/web/code/join).

#### License
----

[Apache-2.0](https://spdx.org/licenses/Apache-2.0.html)
