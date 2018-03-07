package org.openbaton.drivers.openstack4j;

import com.google.gson.GsonBuilder;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.openbaton.catalogue.mano.common.DeploymentFlavour;
import org.openbaton.catalogue.mano.common.SubnetIp;
import org.openbaton.catalogue.mano.descriptor.VNFDConnectionPoint;
import org.openbaton.catalogue.nfvo.Quota;
import org.openbaton.catalogue.nfvo.images.BaseNfvImage;
import org.openbaton.catalogue.nfvo.images.NFVImage;
import org.openbaton.catalogue.nfvo.networks.Network;
import org.openstack4j.api.OSClient;
import org.openstack4j.model.compute.Flavor;
import org.openstack4j.model.compute.QuotaSet;
import org.openstack4j.model.compute.Server;
import org.openstack4j.model.compute.ext.AvailabilityZone;
import org.openstack4j.model.image.Image;
import org.openstack4j.model.network.IP;
import org.openstack4j.model.network.NetQuota;
import org.openstack4j.model.network.Port;
import org.openstack4j.model.network.Subnet;
import org.openstack4j.model.network.options.PortListOptions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class Utils {
  private static Logger log = LoggerFactory.getLogger(Utils.class);
  private static String portNamePrefix = "VNFD-";

  static String buildPortName(VNFDConnectionPoint vnfdConnectionPoint) {
    return portNamePrefix + vnfdConnectionPoint.getId();
  }

  static String getPortNamePrefix() {
    return portNamePrefix;
  }

  static DeploymentFlavour getFlavor(Flavor flavor4j) {
    DeploymentFlavour deploymentFlavour = new DeploymentFlavour();
    deploymentFlavour.setFlavour_key(flavor4j.getName());
    deploymentFlavour.setExtId(flavor4j.getId());
    deploymentFlavour.setDisk(flavor4j.getDisk());
    deploymentFlavour.setRam(flavor4j.getRam());
    deploymentFlavour.setVcpus(flavor4j.getVcpus());
    return deploymentFlavour;
  }

  static org.openbaton.catalogue.nfvo.Server getServer(
      Server server4j, OSClient os, Map<String, String> portNamesAndInterfaceIds) {
    log.trace("Server: " + new GsonBuilder().setPrettyPrinting().create().toJson(server4j));
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

    Map<String, Set<SubnetIp>> ips = new HashMap<String, Set<SubnetIp>>();
    // get a list of all of the ports associated with the server
    PortListOptions options = PortListOptions.create().deviceId(server4j.getId());
    List<? extends Port> ports = os.networking().port().list(options);

    for (Port port : ports) {
      org.openstack4j.model.network.Network network =
          os.networking().network().get(port.getNetworkId());
      if (!ips.containsKey(network.getName())) {
        ips.put(network.getName(), new HashSet<SubnetIp>());
      }

      for (IP ip4j : port.getFixedIps()) {
        SubnetIp subnetIp = new SubnetIp();
        subnetIp.setIp(ip4j.getIpAddress());
        os.networking().subnet().get(ip4j.getSubnetId()).getName();
        subnetIp.setSubnetName(os.networking().subnet().get(ip4j.getSubnetId()).getName());

        if (portNamesAndInterfaceIds.containsKey(port.getName())) {
          subnetIp.setInterfaceId(portNamesAndInterfaceIds.get(port.getName()));
        }

        ips.get(network.getName()).add(subnetIp);
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

  static Map<String, String> getPortNamesAndInterfaceIds(Set<VNFDConnectionPoint> vnfdcps) {
    Map<String, String> interfaces = new HashMap<String, String>();
    for (VNFDConnectionPoint vnfdConnectionPoint : vnfdcps) {
      interfaces.put(
          buildPortName(vnfdConnectionPoint), vnfdConnectionPoint.getInterfaceId().toString());
    }
    return interfaces;
  }

  private static NFVImage getImage(org.openstack4j.model.compute.Image image4j) {
    NFVImage image = new NFVImage();
    image.setName(image4j.getName());
    return image;
  }

  static BaseNfvImage getImage(Image image) {
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

  static org.openbaton.catalogue.nfvo.networks.Subnet getSubnet(Subnet subnet) {
    org.openbaton.catalogue.nfvo.networks.Subnet nfvSubnet =
        new org.openbaton.catalogue.nfvo.networks.Subnet();
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
    nfvNetwork.setSubnets(new HashSet<>());
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

  static org.openbaton.catalogue.nfvo.viminstances.AvailabilityZone getAvailabilityZone(
      AvailabilityZone az) {
    org.openbaton.catalogue.nfvo.viminstances.AvailabilityZone availabilityZone =
        new org.openbaton.catalogue.nfvo.viminstances.AvailabilityZone();
    availabilityZone.setName(az.getZoneName());
    availabilityZone.setAvailable(az.getZoneState().getAvailable());
    availabilityZone.setHosts(new HashMap<>());
    az.getHosts().forEach((k, v) -> v.forEach((k2, v2) -> availabilityZone.getHosts().put(k, k2)));
    return availabilityZone;
  }
}
