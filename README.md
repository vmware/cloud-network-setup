#### cloud-network
----

```cloud-network``` configures network in cloud environment. In cloud environment instances are set public IPs and private IPs. If more than one private IP is configured then except the IP which is provided by DHCP others can't be fetched and configured. This project is adopting towards cloud network environment such as Azure, GCP, Amazon EC2. It fetches the metadata from the metadata server endpoint, parses and then assign IPs and routes. When `cloud-network` is installed, it automatically configures network interfaces in cloud frameworks. Via netlink it detects which interfaces are available. Additionally, for all interfaces including the primary one, it looks up secondary IP addresses from the metadata server endpoint and configures them on the interface, if any.

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

`Address=`

Specifies the IP address which the local REST API server will listen. Defaults to `127.0.0.1`.

`Port=`

Specifies the IP port which the local REST API server will listen. Defaults to `5209`.

`Supplementary=`

A whitespace-separated list of matching the device name. Specifies the interfaces which will be configured a default gateway and routing policy
rules for each Ip address including primary address. Defaults to unset.

Note that when there are multiple interfaces, the secondary interface becomes unreachable. When `Supplementary=` is set, the default route and routing policy
rules are automatically configured.

 ```bash
> cat /etc/cloud-network/cloud-network.toml
[System]
RefreshTimer="300s"
LogLevel="info"
LogFormat="text"

[Network]
Address="127.0.0.1"
Port="5209"
Supplementary="ens3"
```

```bash
❯ > sudo systemctl status cloud-network
● cloud-network.service - Configures network in cloud enviroment
     Loaded: loaded (/usr/lib/systemd/system/cloud-network.service; disabled; vendor preset: enabled)
     Active: active (running) since Mon 2021-05-31 22:54:50 UTC; 3min 31s ago
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
            Name: ens33
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
