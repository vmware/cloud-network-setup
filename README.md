#### cloud-network-setup
----

```cloud-network-setup``` configures network in cloud environment. In cloud environment instances are set public IP and private IP. If more than one private IP is configured then except the IP which is provided by DHCP others can't be fetched and configured via DHCP. This project is adopting towards cloud network enviroment such as Azure, GCP, Amazon EC2. It fetches the metadata from the metadata server endpoint, parses and then assign ip and routes. When `cloud-network-setup` is installed, it automatically configures network interfaces in cloud frameworks.  Via netlink it detects which interfaces are available. Additionally, for all interfaces including the primary one, it looks up secondary IPv4 addresses from the metadata server endpoint and configures them on the interface, if any.

A local RESTful JSON server runs on address `127.0.0.1:5209` and the instance metadata is saved in per link basis in the directory `/run/cloud-network-setup`.

Interface configurations is checked periodically, and in case the configuration in the cloud framework changed, the interface will be reconfigured accordingly.

#### Building from source
----

By simply doing
```bash

❯ make build
❯ sudo make install
```

#### Configuration
----

Configuration file `cloud-network.toml` located in `/etc/cloud-network-setup/` directory to manage the configuration.

The `[System]` section takes following Keys:

`LogLevel=`

Specifies the log level. Takes one of `Trace`, `Debug`, `Info`, `Warning`, `Error`, `Fatal` and `Panic`. Defaults to `info`. See [sirupsen](https://github.com/sirupsen/logrus#level-logging)

`LogFormat=`

Specifies the log format. Takes one of text or json. Takes one of `text` or `json`, Defaults to `text`.

`RefreshTimer=`

Specifies the time interval, is the amount of time taken to retrive the data from metadata endpoint.

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
❯ cat /etc/cloud-network-setup/cloud-network.toml
[System]
RefreshTimer="300s"
LogLevel="info"
LogFormat="text"

[Network]
Address="127.0.0.1"
Port="5209"
```

```bash
❯ sudo systemctl status cloud-network-setup.service
● cloud-network-setup.service - Configures network in cloud enviroment
     Loaded: loaded (/usr/lib/systemd/system/cloud-network-setup.service; disabled; vendor preset: disabled)
     Active: active (running) since Mon 2021-05-17 21:08:14 CEST; 43min ago
   Main PID: 328542 (cloud-network-s)
      Tasks: 9 (limit: 9287)
     Memory: 2.8M
        CPU: 54ms
     CGroup: /system.slice/cloud-network-setup.service
             └─328542 /usr/bin/cloud-network-setup

May 17 21:49:29 Zeus cloud-network-setup[328542]: level=debug msg="Notify service manager watchdog"
May 17 21:49:29 Zeus systemd[1]: cloud-network-setup.service: Got notification message from PID 328542 (WATCHDOG=1)
May 17 21:49:59 Zeus cloud-network-setup[328542]: level=debug msg="Notify service manager watchdog"
May 17 21:49:59 Zeus systemd[1]: cloud-network-setup.service: Got notification message from PID 328542 (WATCHDOG=1)

```

#### cnctl
----

`cnctl` is a CLI tool allows to view metadata, which is retirved from the endpoint metadata server.

```bash
❯ cnctl status system
    Cloud provider: aws
             AmiID: ami-005f15863xxxxxxxx
          Location: 0
BlockDeviceMapping: {Ami:xvda Root:/dev/xvda}
          Hostname: Zeus.us-west-2.compute.internal
    PublicHostname: Zeuspublic.us-west-2.compute.amazonaws.com
     LocalHostname: Zeus.us-west-2.compute.internal
    InstanceAction: none
        InstanceID: i-0c8c1test
 InstanceLifeCycle: on-demand
      InstanceType: t4g.micro
         Placement: {AvailabilityZone:us-west-2d AvailabilityZoneID:usw2-az4 Region:us-west-2}
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

The `cloud-network-setup` project team welcomes contributions from the community. If you wish to contribute code and you have not signed our contributor license agreement (CLA), our bot will update the issue when you open a Pull Request. For any questions about the CLA process, please refer to our [FAQ](https://cla.vmware.com/faq).

slack channel [#photon](https://code.vmware.com/web/code/join).

#### License
----

[Apache-2.0](https://spdx.org/licenses/Apache-2.0.html)
