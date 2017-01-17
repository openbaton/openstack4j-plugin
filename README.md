 <img src="https://raw.githubusercontent.com/openbaton/openbaton.github.io/master/images/openBaton.png" width="250"/>
  
  Copyright © 2015-2016 [Open Baton](http://openbaton.org). Licensed under [Apache v2 License](http://www.apache.org/licenses/LICENSE-2.0).

# Open Baton Openstack4J Driver

This project **openstack4j-plugin** contains an implementation of a driver for integrating Open Baton with OpenStack. This plugin uses the plugin-sdk allowing the NFVO to interoperate with this plugin using AMQP. This plugin uses OpenStack4J as implementation of the OpenStack APIs in Java. This version of the Plugin supports all the OpenStack versions starting from Kilo. In particular, this plugin supports also Keystone V3 APIs. 

## How to install OpenStack4J driver

If you are using source code (git) to install Open Baton, it is recommended that you go to [get.openbaton.org][get-openbaton-org] and download the stable version of the plugin from there. After this you will need to put the jar in the folder that is specified in file /etc/openbaton/openbaton.properties via the property plugin-installation-dir. You can specify where the log of the plugin will be with this parameter nfvo.plugin.log.path.
If you are using debian package then you will be presented with a choice of downloading plugins during the installation process.


You can also clone this project and build it with gradle yourself. After that the placement of the built jar file is the same as for jar that would have been downloaded from the repository.

## How to start the OpenStack4J driver standalone mode

If you have placed the plugin as it was mentioned earlier, then NFVO will automatically start it with the right parameters. The plugin however is by itself an application which can be started remotely by using CLI. For this, you will need to type this into console. 

```bash
$ java -jar path-to-plugin.jar openstack4j [rabbitmq-ip] [rabbitmq-port] [n-of-consumers] [user] [password]
```

* **openstack4j** represents the unique name given to this vim driver 
* **rabbitmq-ip** is the ip of the host where the rabbitmq server is installed and running
* **rabbitmq-port** is the port on which the rabbitmq accepts the messages(it is usually 5672 by default) 
* **number-of-consumers** specifies the number of actors that will accept the requests
* **user** rabbitmq username (default: admin)
* **password** rabbitm password (default: openbaton)


## How to use the OpenStack4J driver

In order to use this driver, the only thing you need to do is to put into your VIM instance JSON file the type of this plugin: **openstack4j**. An example of a VIM instance file using this plugin is: 

In order to interoperate with OpenStack it is required to register the VIM instance responsible for it to the NFVO. 

### Keystone V2

If you are using Keystone V2, the JSON file looks like the following: 

```javascript
{  
   "name":"vim-instance-name",
   "authUrl":"http://192.168.0.5:5000/v2.0",
   "tenant":"tenantName",
   "username":"userName",
   "password":"password",
   "keyPair":"keyName",
   "securityGroups":[  
      "securityName"
   ],
   "type":"openstack4j",
   "location":{  
      "name":"Berlin",
      "latitude":"52.525876",
      "longitude":"13.314400"
   }
}
```

### Keystone V3

In case you are using Keystone V3 you need to put in the tenant field the tenant ID instead of the tenant name. Example: 

```javascript
{  
   "name":"vim-instance-name",
   "authUrl":"http://192.168.0.5:5000/v3",
   "tenant":"ebbdf73e8d394f5cb4bcb8ccc0bc7500",
   "username":"userName",
   "password":"password",
   "keyPair":"keyName",
   "securityGroups":[  
      "securityName"
   ],
   "type":"openstack4j",
   "location":{  
      "name":"Berlin",
      "latitude":"52.525876",
      "longitude":"13.314400"
   }
}
```
 


# What is Open Baton?

Open Baton is an open source project providing a comprehensive implementation of the ETSI Management and Orchestration (MANO) specification and the TOSCA Standard.

Open Baton provides multiple mechanisms for interoperating with different VNFM vendor solutions. It has a modular architecture which can be easily extended for supporting additional use cases. 

It integrates with OpenStack as standard de-facto VIM implementation, and provides a driver mechanism for supporting additional VIM types. It supports Network Service management either using the provided Generic VNFM and Juju VNFM, or integrating additional specific VNFMs. It provides several mechanisms (REST or PUB/SUB) for interoperating with external VNFMs. 

It can be combined with additional components (Monitoring, Fault Management, Autoscaling, and Network Slicing Engine) for building a unique MANO comprehensive solution.

## Source Code and documentation

The Source Code of the other Open Baton projects can be found [here][openbaton-github] and the documentation can be found [here][openbaton-doc]

## News and Website

Check the [Open Baton Website][openbaton]

Follow us on Twitter @[openbaton][openbaton-twitter]

## Licensing and distribution
Copyright © [2015-2016] Open Baton project

Licensed under the Apache License, Version 2.0 (the "License");

you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Support
The Open Baton project provides community support through the Open Baton Public Mailing List and through StackOverflow using the tags openbaton.

## Supported by
  <img src="https://raw.githubusercontent.com/openbaton/openbaton.github.io/master/images/fokus.png" width="250"/><img src="https://raw.githubusercontent.com/openbaton/openbaton.github.io/master/images/tu.png" width="150"/>

[plugin-sdk-link]: https://github.com/openbaton/plugin-sdk
[nfvo-link]: https://github.com/openbaton/NFVO
[generic-link]:https://github.com/openbaton/generic-vnfm
[get-openbaton-org]:http://get.openbaton.org/plugins/stable/
[client-link]: https://github.com/openbaton/openbaton-client
[spring.io]:https://spring.io/
[NFV MANO]:http://docbox.etsi.org/ISG/NFV/Open/Published/gs_NFV-MAN001v010101p%20-%20Management%20and%20Orchestration.pdf
[openbaton]:http://twitter.com/openbaton
[website]:http://openbaton.github.io/
[get-openbaton-org-liberty]:http://get.openbaton.org/plugins/1.0.2-liberty-nighly/
