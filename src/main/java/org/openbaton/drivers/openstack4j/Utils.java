package org.openbaton.drivers.openstack4j;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import org.openbaton.catalogue.mano.common.DeploymentFlavour;
import org.openbaton.catalogue.nfvo.NFVImage;
import org.openbaton.catalogue.nfvo.Network;
import org.openbaton.catalogue.nfvo.Quota;
import org.openstack4j.model.compute.Address;
import org.openstack4j.model.compute.Flavor;
import org.openstack4j.model.compute.QuotaSet;
import org.openstack4j.model.compute.Server;
import org.openstack4j.model.image.Image;
import org.openstack4j.model.network.NetQuota;
import org.openstack4j.model.network.Subnet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Created by lto on 10/01/2017. */
class Utils {
  private static Logger log = LoggerFactory.getLogger(Utils.class);

  static DeploymentFlavour getFlavor(Flavor flavor4j) {
    DeploymentFlavour deploymentFlavour = new DeploymentFlavour();
    deploymentFlavour.setFlavour_key(flavor4j.getName());
    deploymentFlavour.setExtId(flavor4j.getId());
    deploymentFlavour.setDisk(flavor4j.getDisk());
    deploymentFlavour.setRam(flavor4j.getRam());
    deploymentFlavour.setVcpus(flavor4j.getVcpus());
    return deploymentFlavour;
  }

  static org.openbaton.catalogue.nfvo.Server getServer(Server server4j) {
    log.debug("Got Server to parse: " + server4j);
    org.openbaton.catalogue.nfvo.Server server = new org.openbaton.catalogue.nfvo.Server();
    server.setName(server4j.getName());
    server.setExtId(server4j.getId());
    server.setCreated(server4j.getCreated());
    if (server4j.getStatus() != null) {
      if (server4j.getStatus().equals(Server.Status.ERROR)) {
        server.setExtendedStatus(
            "[OpenStack] "
                + server4j.getFault().getCode()
                + ": "
                + server4j.getFault().getMessage());
      } else {
        server.setExtendedStatus(server4j.getStatus().value());
      }
      server.setStatus(server4j.getStatus().value());
    }
    server.setHostName(server4j.getName()); // TODO which one is correct?
    server.setInstanceName(server4j.getInstanceName());
    HashMap<String, List<String>> ips = new HashMap<>();
    if (server4j.getAddresses() != null && server4j.getAddresses().getAddresses() != null) {
      for (Map.Entry<String, List<? extends Address>> address :
          server4j.getAddresses().getAddresses().entrySet()) {
        List<String> adrs = new ArrayList<>();
        for (Address ip : address.getValue()) {
          adrs.add(ip.getAddr());
        }
        ips.put(address.getKey(), adrs);
      }
    }
    server.setIps(ips);
    if (server4j.getFlavor() != null) server.setFlavor(Utils.getFlavor(server4j.getFlavor()));
    if (server4j.getImage() != null) server.setImage(Utils.getImage(server4j.getImage()));
    else if (server4j.getFlavor() != null) server.setFlavor(Utils.getFlavor(server4j.getFlavor()));
    server.setHypervisorHostName(server4j.getHypervisorHostname());
    server.setFloatingIps(new HashMap<String, String>());
    //TODO list floating ips
    //server.setFloatingIps();
    return server;
  }

  private static NFVImage getImage(org.openstack4j.model.compute.Image image4j) {
    NFVImage image = new NFVImage();
    image.setName(image4j.getName());
    return image;
  }

  static NFVImage getImage(Image image) {
    NFVImage nfvImage = new NFVImage();
    nfvImage.setName(image.getName());
    nfvImage.setExtId(image.getId());
    nfvImage.setMinRam(image.getMinRam());
    nfvImage.setMinDiskSpace(image.getMinDisk());
    nfvImage.setCreated(image.getCreatedAt());
    nfvImage.setUpdated(image.getUpdatedAt());
    nfvImage.setIsPublic(image.isPublic());
    nfvImage.setDiskFormat(image.getDiskFormat().toString().toUpperCase());
    nfvImage.setContainerFormat(image.getContainerFormat().toString().toUpperCase());
    nfvImage.setStatus(image.getStatus().value());
    return nfvImage;
  }

  static NFVImage getImageV2(org.openstack4j.model.image.v2.Image image) {
    NFVImage nfvImage = new NFVImage();
    nfvImage.setName(image.getName());
    nfvImage.setExtId(image.getId());
    nfvImage.setMinRam(image.getMinRam());
    nfvImage.setMinDiskSpace(image.getMinDisk());
    nfvImage.setCreated(image.getCreatedAt());
    nfvImage.setUpdated(image.getUpdatedAt());
    nfvImage.setIsPublic(!image.getIsProtected());
    nfvImage.setDiskFormat(image.getDiskFormat().toString().toUpperCase());
    nfvImage.setContainerFormat(image.getContainerFormat().toString().toUpperCase());
    nfvImage.setStatus(String.valueOf(image.getStatus()));
    return nfvImage;
  }

  static org.openbaton.catalogue.nfvo.Subnet getSubnet(Subnet subnet) {
    org.openbaton.catalogue.nfvo.Subnet nfvSubnet = new org.openbaton.catalogue.nfvo.Subnet();
    nfvSubnet.setExtId(subnet.getId());
    nfvSubnet.setName(subnet.getName());
    nfvSubnet.setCidr(subnet.getCidr());
    nfvSubnet.setGatewayIp(subnet.getGateway());
    nfvSubnet.setNetworkId(subnet.getNetworkId());
    return nfvSubnet;
  }

  static Network getNetwork(org.openstack4j.model.network.Network network) {
    Network nfvNetwork = new Network();
    nfvNetwork.setName(network.getName());
    nfvNetwork.setExtId(network.getId());
    nfvNetwork.setExternal(network.isRouterExternal());
    nfvNetwork.setSubnets(new HashSet<org.openbaton.catalogue.nfvo.Subnet>());
    return nfvNetwork;
  }

  static Quota getQuota(QuotaSet qs, NetQuota netQuota, String tenantId) {
    Quota quota = new Quota();
    quota.setTenant(tenantId);
    quota.setCores(qs.getCores());
    quota.setFloatingIps(netQuota.getFloatingIP());
    quota.setInstances(qs.getInstances());
    quota.setKeyPairs(qs.getKeyPairs());
    quota.setRam(qs.getRam());
    return quota;
  }
}
