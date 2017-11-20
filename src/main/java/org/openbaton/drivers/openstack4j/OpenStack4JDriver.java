/*
 * Copyright (c) 2017 Open Baton (http://www.openbaton.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.openbaton.drivers.openstack4j;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.net.util.SubnetUtils;
import org.openbaton.catalogue.mano.common.DeploymentFlavour;
import org.openbaton.catalogue.mano.descriptor.VNFDConnectionPoint;
import org.openbaton.catalogue.nfvo.Quota;
import org.openbaton.catalogue.nfvo.Server;
import org.openbaton.catalogue.nfvo.images.BaseNfvImage;
import org.openbaton.catalogue.nfvo.images.NFVImage;
import org.openbaton.catalogue.nfvo.networks.BaseNetwork;
import org.openbaton.catalogue.nfvo.networks.Network;
import org.openbaton.catalogue.nfvo.networks.Subnet;
import org.openbaton.catalogue.nfvo.viminstances.BaseVimInstance;
import org.openbaton.catalogue.nfvo.viminstances.OpenstackVimInstance;
import org.openbaton.catalogue.security.Key;
import org.openbaton.exceptions.NotFoundException;
import org.openbaton.exceptions.VimDriverException;
import org.openbaton.exceptions.VimException;
import org.openbaton.plugin.PluginStarter;
import org.openbaton.vim.drivers.interfaces.VimDriver;
import org.openstack4j.api.Builders;
import org.openstack4j.api.OSClient;
import org.openstack4j.api.exceptions.AuthenticationException;
import org.openstack4j.core.transport.Config;
import org.openstack4j.model.common.ActionResponse;
import org.openstack4j.model.common.Identifier;
import org.openstack4j.model.common.Payload;
import org.openstack4j.model.common.Payloads;
import org.openstack4j.model.compute.Address;
import org.openstack4j.model.compute.Flavor;
import org.openstack4j.model.compute.QuotaSet;
import org.openstack4j.model.compute.ServerCreate;
import org.openstack4j.model.compute.builder.ServerCreateBuilder;
import org.openstack4j.model.compute.ext.AvailabilityZone;
import org.openstack4j.model.identity.v2.Tenant;
import org.openstack4j.model.identity.v3.Project;
import org.openstack4j.model.identity.v3.Region;
import org.openstack4j.model.image.Image;
import org.openstack4j.model.network.AttachInterfaceType;
import org.openstack4j.model.network.IPVersionType;
import org.openstack4j.model.network.NetFloatingIP;
import org.openstack4j.model.network.NetQuota;
import org.openstack4j.model.network.Router;
import org.openstack4j.model.network.RouterInterface;
import org.openstack4j.openstack.OSFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

/** Created by gca on 10/01/17. */
public class OpenStack4JDriver extends VimDriver {

  private Logger log = LoggerFactory.getLogger(OpenStack4JDriver.class);
  private static Lock lock;

  public OpenStack4JDriver() {
    super();
    init();
  }

  private void init() {
    String sslChecksDisabled = properties.getProperty("disable-ssl-certificate-checks", "false");
    log.debug("Disable SSL certificate checks: {}", sslChecksDisabled);
    OpenStack4JDriver.lock = new ReentrantLock();
  }

  public OSClient authenticate(OpenstackVimInstance vimInstance) throws VimDriverException {

    OSClient os;
    Config cfg = Config.DEFAULT;
    cfg =
        cfg.withConnectionTimeout(
            Integer.parseInt(properties.getProperty("connection-timeout", "10000")));
    try {
      if (isV3API(vimInstance)) {

        Identifier domain = Identifier.byName("Default");
        Identifier project = Identifier.byId(vimInstance.getTenant());

        String[] domainProjectSplit = vimInstance.getTenant().split(Pattern.quote(":"));
        if (domainProjectSplit.length == 2) {
          log.trace("Found domain name and project id: " + Arrays.toString(domainProjectSplit));
          domain = Identifier.byName(domainProjectSplit[0]);
          project = Identifier.byId(domainProjectSplit[1]);
        }

        log.trace("Domain id: " + domain.getId());
        log.trace("Project id: " + project.getId());

        os =
            OSFactory.builderV3()
                .endpoint(vimInstance.getAuthUrl())
                .scopeToProject(project)
                .credentials(vimInstance.getUsername(), vimInstance.getPassword(), domain)
                .withConfig(cfg)
                .authenticate();
        if (vimInstance.getLocation() != null
            && vimInstance.getLocation().getName() != null
            && !vimInstance.getLocation().getName().isEmpty()) {
          try {
            Region region =
                ((OSClient.OSClientV3) os)
                    .identity()
                    .regions()
                    .get(vimInstance.getLocation().getName());

            if (region != null) {
              ((OSClient.OSClientV3) os).useRegion(vimInstance.getLocation().getName());
            }
          } catch (Exception ignored) {
            log.warn(
                "Not found region '"
                    + vimInstance.getLocation().getName()
                    + "'. Use default one...");
            return os;
          }
        }
      } else {
        os =
            OSFactory.builderV2()
                .endpoint(vimInstance.getAuthUrl())
                .credentials(vimInstance.getUsername(), vimInstance.getPassword())
                .tenantName(vimInstance.getTenant())
                .withConfig(cfg)
                .authenticate();
        if (vimInstance.getLocation() != null
            && vimInstance.getLocation().getName() != null
            && !vimInstance.getLocation().getName().isEmpty()) {
          try {
            ((OSClient.OSClientV2) os).useRegion(vimInstance.getLocation().getName());
            ((OSClient.OSClientV2) os).identity().listTokenEndpoints();
          } catch (Exception e) {
            log.warn(
                "Not found region '"
                    + vimInstance.getLocation().getName()
                    + "'. Use default one...");
            ((OSClient.OSClientV2) os).removeRegion();
          }
        }
      }
    } catch (AuthenticationException e) {
      throw new VimDriverException(e.getMessage(), e);
    }

    return os;
  }

  private boolean isV3API(BaseVimInstance vimInstance) {
    return vimInstance.getAuthUrl().endsWith("/v3") || vimInstance.getAuthUrl().endsWith("/v3.0");
  }

  public static void main(String[] args)
      throws NoSuchMethodException, IOException, InstantiationException, TimeoutException,
          IllegalAccessException, InvocationTargetException, InterruptedException {
    if (args.length == 4) {
      PluginStarter.registerPlugin(
          OpenStack4JDriver.class,
          args[0],
          args[1],
          Integer.parseInt(args[2]),
          Integer.parseInt(args[3]));
    } else {
      PluginStarter.registerPlugin(OpenStack4JDriver.class, "openstack", "localhost", 5672, 10);
    }
  }

  @Override
  public Server launchInstance(
      BaseVimInstance vimInstance,
      String name,
      String image,
      String flavor,
      String keypair,
      Set<VNFDConnectionPoint> vnfdConnectionPoints,
      Set<String> secGroup,
      String userData)
      throws VimDriverException {
    Server server;
    try {
      OpenstackVimInstance openstackVimInstance = (OpenstackVimInstance) vimInstance;
      OSClient os = this.authenticate(openstackVimInstance);
      String tenantId =
          isV3API(openstackVimInstance)
          ? openstackVimInstance.getTenant()
          : getTenantFromName(os, openstackVimInstance.getTenant());
      List<String> osNetworkIds = getNetworkIdsFromNames(os, tenantId, vnfdConnectionPoints);

      String imageId = getImageIdFromName(vimInstance, image);
      log.debug("imageId: " + imageId);
      org.openstack4j.model.image.Image imageFromVim = os.images().get(imageId);
      log.trace("Image received from VIM: " + imageFromVim);
      if (imageFromVim == null) {
        throw new VimException("Not found image " + image + " on VIM " + vimInstance.getName());
      } else if (imageFromVim.getStatus() == null
          || imageFromVim.getStatus() != (org.openstack4j.model.image.Image.Status.ACTIVE)) {
        throw new VimException("Image " + image + " is not yet in active. Try again later...");
      }
      Flavor flavor4j = getFlavorFromName(vimInstance, flavor);
      flavor = flavor4j.getId();
      Optional<? extends AvailabilityZone> availabilityZone = getZone(os, vimInstance);
      ServerCreate sc;
      // name, flavor, imageId, user-data and network are mandatory
      ServerCreateBuilder serverCreateBuilder =
          Builders.server()
              .name(name)
              .flavor(flavor)
              .image(imageId)
              .networks(osNetworkIds)
              .userData(new String(Base64.encodeBase64(userData.getBytes())));

      // check if keypair is not null and is not equal empty string
      if (keypair != null && !keypair.equals("")) {
        serverCreateBuilder.keypairName(keypair);
      }

      availabilityZone.ifPresent(zone -> serverCreateBuilder.availabilityZone(zone.getZoneName()));

      // temporary workaround for getting first security group as it seems not supported adding multiple security groups
      secGroup.forEach(serverCreateBuilder::addSecurityGroup);

      // creating ServerCreate object
      sc = serverCreateBuilder.build();

      for (VNFDConnectionPoint vnfdConnectionPoint : vnfdConnectionPoints) {
        if (vnfdConnectionPoint.getFixedIp() != null
            && !vnfdConnectionPoint.getFixedIp().equals("")) {
          sc.addNetwork(
              getNetworkById(vimInstance, vnfdConnectionPoint.getVirtual_link_reference_id())
                  .getExtId(),
              vnfdConnectionPoint.getFixedIp());
        }
      }
      // createing ServerCreate object
      sc = serverCreateBuilder.build();

      log.debug(
          "Keypair: "
              + keypair
              + ", SecGroup, "
              + secGroup
              + ", imageId: "
              + imageId
              + ", flavorId: "
              + flavor
              + ", networks: "
              + osNetworkIds);
      org.openstack4j.model.compute.Server server4j = os.compute().servers().boot(sc);
      server = Utils.getServer(server4j);
    } catch (Exception e) {
      log.error(e.getMessage(), e);
      throw new VimDriverException(e.getMessage());
    }
    return server;
  }

  private Optional<? extends AvailabilityZone> getZone(OSClient os, BaseVimInstance vimInstance) throws Exception {
    String az = vimInstance.getMetadata().get("az");
    if (az == null)
      return Optional.empty();
    log.debug(        "Looking for availability zone with name: "        + az);
    List<? extends AvailabilityZone> availabilityZones = os.compute().zones().list();
    return availabilityZones.stream().filter(availabilityZone -> availabilityZone.getZoneName().equals(az)).findAny();
  }

  private Set<VNFDConnectionPoint> fixVNFDConnectionPoint(Set<VNFDConnectionPoint> networks) {
    //    Collections.sort(networkList, new NetworkComparator());

    Gson gson = new Gson();
    String oldVNFDCP = gson.toJson(networks);

    //    VNFDConnectionPoint[] vnfdConnectionPoints = newNetworks.toArray(new VNFDConnectionPoint[0]);
    //    Arrays.sort(
    //        vnfdConnectionPoints,
    //        new Comparator<VNFDConnectionPoint>() {
    //          @Override
    //          public int compare(VNFDConnectionPoint o1, VNFDConnectionPoint o2) {
    //            return o1.getInterfaceId() - o2.getInterfaceId();
    //          }
    //        });
    return gson.fromJson(oldVNFDCP, new TypeToken<Set<VNFDConnectionPoint>>() {}.getType());
  }

  private Flavor getFlavorFromName(BaseVimInstance vimInstance, String flavor)
      throws VimDriverException {
    OSClient os = authenticate((OpenstackVimInstance) vimInstance);
    for (Flavor flavor4j : os.compute().flavors().list()) {
      if (flavor4j.getName().equals(flavor) || flavor4j.getId().equals(flavor)) {
        return flavor4j;
      }
    }
    throw new VimDriverException("Flavor with name " + flavor + " was not found");
  }

  private List<String> getNetworkIdsFromNames(
      OSClient os, String tenantId, Set<VNFDConnectionPoint> networks)
      throws VimDriverException {
    List<String> res = new LinkedList<>();


    List<VNFDConnectionPoint> vnfdConnectionPoints = new ArrayList<>();
    vnfdConnectionPoints.addAll(networks);
    vnfdConnectionPoints.sort(Comparator.comparing(VNFDConnectionPoint::getInterfaceId));

    for (VNFDConnectionPoint vnfdConnectionPoint : vnfdConnectionPoints) {
      if (vnfdConnectionPoint.getFixedIp() == null || vnfdConnectionPoint.getFixedIp().equals("")) {
        if (vnfdConnectionPoint.getVirtual_link_reference_id() != null
            && !vnfdConnectionPoint.getVirtual_link_reference_id().equals("")) {
          res.add(vnfdConnectionPoint.getVirtual_link_reference_id());
        } else {
          List<? extends org.openstack4j.model.network.Network> networkList =
              os.networking().network().list();
          boolean networkExists = false;
          for (org.openstack4j.model.network.Network network4j : networkList) {
            log.trace("Network " + network4j.getName() + " is shared? " + network4j.isShared());
            if ((vnfdConnectionPoint.getVirtual_link_reference().equals(network4j.getName())
                    || vnfdConnectionPoint.getVirtual_link_reference().equals(network4j.getId()))
                && (network4j.getTenantId().equals(tenantId) || network4j.isShared())) {
              if (!res.contains(network4j.getId())) {
                res.add(network4j.getId());
                networkExists = true;
                break;
              }
            }
          }
          if (!networkExists) {
            throw new VimDriverException(
                "Not found Network '"
                    + vnfdConnectionPoint.getVirtual_link_reference()
                    + "'. Consider to refresh the VIM manually and try again ...");
          }
        }
      }
    }
    log.debug("Found external network id without fixed ip: " + res);
    return res;
  }

  private String getImageIdFromName(BaseVimInstance vimInstance, String imageName)
      throws VimDriverException {
    log.info("Getting image id of " + imageName + " on " + vimInstance.getName());
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    for (BaseNfvImage image4j : this.listImages(vimInstance)) {
      if (((NFVImage)image4j).getName().equals(imageName) || image4j.getExtId().equals(imageName)) {
        return image4j.getExtId();
      }
    }
    throw new VimDriverException("Not found image '" + imageName + "' on " + vimInstance.getName());
  }

  private List<NetFloatingIP> listFloatingIps(OSClient os, BaseVimInstance vimInstance)
      throws VimDriverException {
    OpenstackVimInstance openstackVimInstance = (OpenstackVimInstance) vimInstance;
    log.info("Listing all floating IPs of " + vimInstance.getName());
    List<? extends NetFloatingIP> floatingIPs = os.networking().floatingip().list();

    List<NetFloatingIP> res = new ArrayList<>();
    for (NetFloatingIP floatingIP : floatingIPs) {
      if (isV3API(vimInstance) && floatingIP.getTenantId().equals(openstackVimInstance.getTenant())
          || (!isV3API(vimInstance)
              && floatingIP.getTenantId().equals(getTenantFromName(os, openstackVimInstance.getTenant())))) {
        if (floatingIP.getFixedIpAddress() == null || floatingIP.getFixedIpAddress().equals("")) {
          res.add(floatingIP);
        }
      }
    }
    return res;
  }


  @Override
  public List<BaseNfvImage> listImages(BaseVimInstance vimInstance) throws VimDriverException {
    try {
      OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
      Map<String, String> map = new HashMap<>();
      map.put("limit", "100");
      List<? extends Image> images = os.images().list(map);
      List<BaseNfvImage> nfvImages = new ArrayList<>();
      for (Image image : images) {
        nfvImages.add(Utils.getImage(image));
      }
      log.info(
          "Listed images for BaseVimInstance with name: "
              + vimInstance.getName()
              + " -> Images: "
              + images);

      return nfvImages;
    } catch (Exception e) {
      log.error(e.getMessage(), e);
      throw new VimDriverException(e.getMessage());
    }
  }

  @Override
  public List<Server> listServer(BaseVimInstance vimInstance) throws VimDriverException {
    OpenstackVimInstance openstackVimInstance = (OpenstackVimInstance) vimInstance;
    List<Server> obServers = new ArrayList<>();
    try {
      OSClient os = this.authenticate(openstackVimInstance);

      List<? extends org.openstack4j.model.compute.Server> servers = os.compute().servers().list();
      for (org.openstack4j.model.compute.Server srv : servers) {
        if ((isV3API(vimInstance) && srv.getTenantId().equals(openstackVimInstance.getTenant())
            || (!isV3API(vimInstance)
                && srv.getTenantId().equals(getTenantFromName(os, openstackVimInstance.getTenant()))))) {
          obServers.add(Utils.getServer(srv));
        }
      }
    } catch (Exception e) {
      log.error(e.getMessage(), e);
      throw new VimDriverException(e.getMessage());
    }
    return obServers;
  }

  @Override
  public List<BaseNetwork> listNetworks(BaseVimInstance vimInstance) throws VimDriverException {
    try {
      OpenstackVimInstance openstackVimInstance = (OpenstackVimInstance) vimInstance;
      OSClient os = this.authenticate(openstackVimInstance);
      List<? extends org.openstack4j.model.network.Network> networks =
          os.networking().network().list();
      log.info("Received all networks: " + networks);
      List<BaseNetwork> nfvNetworks = new ArrayList<>();
      for (org.openstack4j.model.network.Network network : networks) {
        if ((network.isRouterExternal() || network.isShared())
            || (isV3API(vimInstance) && network.getTenantId().equals(openstackVimInstance.getTenant())
                || (!isV3API(vimInstance)
                    && network
                        .getTenantId()
                        .equals(getTenantFromName(os, openstackVimInstance.getTenant()))))) {
          Network nfvNetwork = Utils.getNetwork(network);
          if (network.getSubnets() != null && !network.getSubnets().isEmpty()) {
            for (String subnetId : network.getSubnets()) {
              Subnet subnet = getSubnetById(os, vimInstance, subnetId);
              if (subnet == null) {
                continue;
              }
              nfvNetwork.getSubnets().add(subnet);
            }
          }
          nfvNetworks.add(nfvNetwork);
        }
      }
      return nfvNetworks;
    } catch (Exception e) {
      log.error(e.getMessage(), e);
      throw new VimDriverException(e.getMessage());
    }
  }

  private String getTenantFromName(OSClient os, String tenantName) throws VimDriverException {
    log.trace("Get tenant id of tenant " + tenantName);
    String tenantId = null;
    if (os.supportsIdentity()) {
      if (os instanceof OSClient.OSClientV2) {
        List<? extends Tenant> tenants = ((OSClient.OSClientV2) os).identity().tenants().list();
        log.trace("Available tenants (v2): " + tenants);
        for (Tenant currentTenant : tenants) {
          if (currentTenant.getName().equals(tenantName)) {
            tenantId = currentTenant.getId();
            break;
          }
        }
      } else {
        log.trace(
            "Available tenants (v3): " + ((OSClient.OSClientV3) os).identity().projects().list());
        for (Project currentTenant : ((OSClient.OSClientV3) os).identity().projects().list()) {
          if (currentTenant.getName().equals(tenantName)) {
            tenantId = currentTenant.getId();
            break;
          }
        }
      }
      //Tenant tenant = ((OSClient.OSClientV2) os).identity().tenants().getByName(tenantName);
      log.trace("Found tenant " + tenantName + ": " + tenantId);
      return tenantId;
    }
    throw new VimDriverException(
        "Not found tenant " + tenantName + " on VIM with endpoint " + os.getEndpoint());
  }

  private Subnet getSubnetById(OSClient os, BaseVimInstance vimInstance, String subnetId)
      throws VimDriverException, NotFoundException {
    log.debug(
        "Getting Subnet with extId: "
            + subnetId
            + " from BaseVimInstance with name: "
            + vimInstance.getName());
    try {
      org.openstack4j.model.network.Subnet subnet = os.networking().subnet().get(subnetId);
      log.debug("Found subnet: " + subnet);
      if (subnet != null) {
        return Utils.getSubnet(subnet);
      } else {
        return null;
      }
    } catch (Exception e) {
      log.error(e.getMessage(), e);
      throw new VimDriverException(e.getMessage());
    }
  }

  @Override
  public List<DeploymentFlavour> listFlavors(BaseVimInstance vimInstance) throws VimDriverException {
    List<DeploymentFlavour> deploymentFlavours = new ArrayList<>();
    try {
      OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
      List<? extends Flavor> flavors = os.compute().flavors().list();
      for (Flavor flavor : flavors) {
        deploymentFlavours.add(Utils.getFlavor(flavor));
      }
    } catch (Exception e) {
      log.error(e.getMessage(), e);
      throw new VimDriverException(e.getMessage());
    }
    return deploymentFlavours;
  }

  @Override
  public BaseVimInstance refresh(BaseVimInstance vimInstance) throws VimDriverException {
    OpenstackVimInstance openstackVimInstance = (OpenstackVimInstance) vimInstance;

    List<BaseNfvImage> newImages = listImages(vimInstance);
    List<String> newImageIds = new ArrayList<>();
    newImages.forEach(i -> newImageIds.add(i.getExtId()));
    if (openstackVimInstance.getImages() == null) {
      openstackVimInstance.setImages(new HashSet<>());
    } else {
      openstackVimInstance.getImages().clear();
    }
    openstackVimInstance.addAllImages(newImages);

    List<BaseNetwork> newNetworks = listNetworks(vimInstance);
    List<String> newNetworkIds = new ArrayList<>();
    newNetworks.forEach(i -> newNetworkIds.add(i.getExtId()));
    if (openstackVimInstance.getNetworks() == null) {
      openstackVimInstance.setNetworks(new HashSet<>());
    } else {
      openstackVimInstance.getNetworks().clear();
    }
    openstackVimInstance.addAllNetworks(newNetworks);

    List<DeploymentFlavour> newFlavors = listFlavors(vimInstance);
    List<String> newFlavorIds = new ArrayList<>();
    newFlavors.forEach(i -> newFlavorIds.add(i.getExtId()));
    if (openstackVimInstance.getFlavours() == null) {
      openstackVimInstance.setFlavours(new HashSet<>());
    } else {
      openstackVimInstance.getFlavours().clear();
    }
    openstackVimInstance.getFlavours().clear();
    openstackVimInstance.getFlavours().addAll(newFlavors);

    List<org.openbaton.catalogue.nfvo.viminstances.AvailabilityZone> newAvalabilityZones= listAvailabilityZone(vimInstance);
    List<String> newAzNames = new ArrayList<>();
    newAvalabilityZones.forEach(i -> newAzNames.add(i.getName()));
    if (openstackVimInstance.getZones() == null) {
      openstackVimInstance.setZones(new HashSet<>());
    } else {
      openstackVimInstance.getZones().clear();
    }
    openstackVimInstance.getZones().clear();
    openstackVimInstance.getZones().addAll(newAvalabilityZones);

    return openstackVimInstance;
  }

  private List<org.openbaton.catalogue.nfvo.viminstances.AvailabilityZone> listAvailabilityZone(BaseVimInstance vimInstance) throws
                                                                                                                             VimDriverException {
    List<org.openbaton.catalogue.nfvo.viminstances.AvailabilityZone> res = new ArrayList<>();
    for (AvailabilityZone az : authenticate((OpenstackVimInstance) vimInstance).compute().zones().list()){
      res.add(Utils.getAvailabilityZone(az));
    }
    return res;
  }

  @Override
  public Server launchInstanceAndWait(
      BaseVimInstance vimInstance,
      String name,
      String image,
      String flavor,
      String keyPair,
      Set<VNFDConnectionPoint> networks,
      Set<String> securityGroups,
      String userdata,
      Map<String, String> floatingIps,
      Set<Key> keys)
      throws VimDriverException {
    networks = fixVNFDConnectionPoint(networks);
    boolean bootCompleted = false;
    if (keys != null && !keys.isEmpty()) {
      userdata = addKeysToUserData(userdata, keys);
    }
    if (userdata == null) {
      userdata = "";
    }
    log.trace("Userdata: " + userdata);

    Server server =
        this.launchInstance(
            vimInstance, name, image, flavor, keyPair, networks, securityGroups, userdata);
    try {
      org.openstack4j.model.compute.Server server4j = null;
      log.info(
          "Deployed VM ( "
              + server.getName()
              + " ) with extId: "
              + server.getExtId()
              + " in status "
              + server.getStatus());
      while (!bootCompleted) {
        log.debug("Waiting for VM with hostname: " + name + " to finish the launch");
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
        server4j = getServerById(vimInstance, server.getExtId());
        server = Utils.getServer(server4j);
        if (server.getStatus().equalsIgnoreCase("ACTIVE")) {
          log.debug("Finished deployment of VM with hostname: " + name);
          bootCompleted = true;
        }
        if (server.getExtendedStatus().equalsIgnoreCase("ERROR")
            || server.getStatus().equalsIgnoreCase("ERROR")) {
          log.error("Failed to launch VM with hostname: " + name + " -> " + server4j.getFault());
          VimDriverException vimDriverException =
              new VimDriverException(server.getExtendedStatus());
          vimDriverException.setServer(server);
          throw vimDriverException;
        }
      }
      if (server.getFloatingIps() == null) {
        server.setFloatingIps(new HashMap<>());
      }
      if (floatingIps != null && floatingIps.size() > 0) {
        OpenStack4JDriver.lock.lock(); // TODO chooseFloating ip is lock but association is parallel
        log.debug("Assigning FloatingIPs to VM with hostname: " + name);
        log.debug("FloatingIPs are: " + floatingIps);
        OpenstackVimInstance openstackVimInstance = (OpenstackVimInstance) vimInstance;
        int freeIps = listFloatingIps(this.authenticate(openstackVimInstance), vimInstance).size();
        int ipsNeeded = floatingIps.size();
        if (freeIps < ipsNeeded) {
          log.error(
              "Insufficient number of ips allocated to tenant, will try to allocate more ips from pool");
          log.debug("Getting the pool name of a floating ip pool");
          for (Map.Entry<String, String> entry : floatingIps.entrySet()) {
            for (VNFDConnectionPoint vnfdConnectionPoint : networks) {
              String poolName;
              if (vnfdConnectionPoint.getChosenPool() != null
                  && !vnfdConnectionPoint.getChosenPool().equals("")
                  && entry.getKey().equals(vnfdConnectionPoint.getVirtual_link_reference())) {
                poolName = vnfdConnectionPoint.getChosenPool();
              } else {
                poolName = getIpPoolName(vimInstance);
              }
              allocateFloatingIps(vimInstance, poolName, ipsNeeded - freeIps);
            }
          }
        }
        if (listFloatingIps(this.authenticate(openstackVimInstance), vimInstance).size()
            >= floatingIps.size()) {
          for (Map.Entry<String, String> fip : floatingIps.entrySet()) {
            server
                .getFloatingIps()
                .put(
                    fip.getKey(),
                    this.translateToNAT(associateFloatingIpToNetwork(vimInstance, server4j, fip)));
          }
          log.info(
              "Assigned FloatingIPs to VM with hostname: "
                  + name
                  + " -> FloatingIPs: "
                  + server.getFloatingIps());
        } else {
          log.error(
              "Cannot assign FloatingIPs to VM with hostname: "
                  + name
                  + ". No FloatingIPs left...");
          VimDriverException exception =
              new VimDriverException(
                  "Cannot assign FloatingIPs to VM with hostname: "
                      + name
                      + ". No FloatingIPs left...");
          exception.setServer(server);
          throw exception;
        }
        OpenStack4JDriver.lock.unlock();
      }
    } catch (Exception e) {
      log.error(e.getMessage());
      VimDriverException exception = new VimDriverException(e.getMessage(), e);
      if (server != null) {
        exception.setServer(server);
      }
      throw exception;
    }
    log.info("Finish association of FIPs if any for server: " + server);
    return server;
  }

  private String translateToNAT(String floatingIp) throws UnknownHostException {

    Properties natRules = new Properties();
    try {
      File file = new File("/etc/openbaton/plugin/openstack4j/nat-translation-rules.properties");
      if (file.exists()) {
        natRules.load(new FileInputStream(file));
      } else {
        natRules.load(
            OpenStack4JDriver.class.getResourceAsStream("/nat-translation-rules.properties"));
      }
    } catch (IOException e) {
      log.warn("no translation rules!");
      return floatingIp;
    }

    for (Map.Entry<Object, Object> entry : natRules.entrySet()) {
      String fromCidr = (String) entry.getKey();
      String toCidr = (String) entry.getValue();
      log.debug("cidr is: " + fromCidr);
      SubnetUtils utilsFrom = new SubnetUtils(fromCidr);
      SubnetUtils utilsTo = new SubnetUtils(toCidr);

      SubnetUtils.SubnetInfo subnetInfoFrom = utilsFrom.getInfo();
      SubnetUtils.SubnetInfo subnetInfoTo = utilsTo.getInfo();
      InetAddress floatingIpNetAddr = InetAddress.getByName(floatingIp);
      if (subnetInfoFrom.isInRange(floatingIp)) { //translation!

        log.debug("From networkMask " + subnetInfoFrom.getNetmask());
        log.debug("To networkMask " + subnetInfoTo.getNetmask());
        if (!subnetInfoFrom.getNetmask().equals(subnetInfoTo.getNetmask())) {
          log.error("Not translation possible, netmasks are different");
          return floatingIp;
        }
        byte[] host = new byte[4];
        for (int i = 0; i < floatingIpNetAddr.getAddress().length; i++) {
          byte value =
              (byte)
                  (floatingIpNetAddr.getAddress()[i]
                      | InetAddress.getByName(subnetInfoFrom.getNetmask()).getAddress()[i]);
          if (value == -1) {
            host[i] = 0;
          } else host[i] = value;
        }

        byte[] netaddress = InetAddress.getByName(subnetInfoTo.getNetworkAddress()).getAddress();
        String[] result = new String[4];
        for (int i = 0; i < netaddress.length; i++) {
          int intValue = new Byte((byte) (netaddress[i] | Byte.valueOf(host[i]))).intValue();
          if (intValue < 0) intValue = intValue & 0xFF;
          result[i] = String.valueOf(intValue);
        }

        return String.join(".", result);
      }
    }
    return floatingIp;
  }

  private org.openstack4j.model.compute.Server getServerById(BaseVimInstance vimInstance, String extId)
      throws VimDriverException {
    OSClient os = authenticate((OpenstackVimInstance) vimInstance);
    return os.compute().servers().get(extId);
  }

  private String associateFloatingIpToNetwork(
      BaseVimInstance vimInstance,
      org.openstack4j.model.compute.Server server4j,
      Map.Entry<String, String> fip)
      throws VimDriverException {

    OSClient os = authenticate((OpenstackVimInstance) vimInstance);

    boolean success = true;
    String floatingIpAddress = "";
    for (Address privateIp : server4j.getAddresses().getAddresses().get(fip.getKey())) {
      floatingIpAddress = findFloatingIpId(os, fip.getValue(), vimInstance).getFloatingIpAddress();
      success =
          success
              && os.compute()
                  .floatingIps()
                  .addFloatingIP(server4j, privateIp.getAddr(), floatingIpAddress)
                  .isSuccess();
    }

    if (success) {
      return floatingIpAddress;
    }
    throw new VimDriverException(
        "Not able to associate fip " + fip + " to instance " + server4j.getName());
  }

  private NetFloatingIP findFloatingIpId(OSClient os, String fipValue, BaseVimInstance vimInstance)
      throws VimDriverException {
    if (fipValue.trim().equalsIgnoreCase("random") || fipValue.trim().equals("")) {
      return listFloatingIps(os, vimInstance).get(0);
    }
    for (NetFloatingIP floatingIP : os.networking().floatingip().list()) {
      if (floatingIP.getFloatingIpAddress().equalsIgnoreCase(fipValue)) {
        return floatingIP;
      }
    }
    throw new VimDriverException("Floating ip " + fipValue + " not found");
  }

  private void allocateFloatingIps(BaseVimInstance vimInstance, String poolName, int numOfFip)
      throws VimDriverException {
    OSClient os = authenticate((OpenstackVimInstance) vimInstance);
    for (int i = 0; i < numOfFip; i++) {
      os.compute().floatingIps().allocateIP(poolName);
    }
  }

  private String getIpPoolName(BaseVimInstance vimInstance) throws VimDriverException {
    OSClient os = authenticate((OpenstackVimInstance) vimInstance);
    List<String> poolNames = os.compute().floatingIps().getPoolNames();
    log.debug("Available Floating IP pools: " + poolNames);
    if (!poolNames.isEmpty()) {
      //TODO select right pool!
      return poolNames.get(0);
    }
    throw new VimDriverException("No pool of floating ips is available");
  }

  @Override
  public Server launchInstanceAndWait(
      BaseVimInstance vimInstance,
      String hostname,
      String image,
      String extId,
      String keyPair,
      Set<VNFDConnectionPoint> networks,
      Set<String> securityGroups,
      String userdata)
      throws VimDriverException {
    return launchInstanceAndWait(
        vimInstance,
        hostname,
        image,
        extId,
        keyPair,
        networks,
        securityGroups,
        userdata,
        null,
        null);
  }

  private String addKeysToUserData(
      String userData, Set<org.openbaton.catalogue.security.Key> keys) {
    log.debug("Going to add all keys: " + keys.size());
    userData += "\n";
    userData += "for x in `find /home/ -name authorized_keys`; do\n";
    /* doing this for avoiding a serialization error of gson */
    Gson gson = new Gson();
    String oldKeys = gson.toJson(keys);
    Set<org.openbaton.catalogue.security.Key> keysSet =
        gson.fromJson(
            oldKeys, new TypeToken<Set<org.openbaton.catalogue.security.Key>>() {}.getType());

    StringBuilder userDataBuilder = new StringBuilder(userData);
    for (org.openbaton.catalogue.security.Key key : keysSet) {
      log.debug("Adding key: " + key.getName());
      userDataBuilder.append("\techo \"").append(key.getPublicKey()).append("\" >> $x\n");
    }
    userData = userDataBuilder.toString();
    userData += "done\n";
    return userData;
  }

  @Override
  public void deleteServerByIdAndWait(BaseVimInstance vimInstance, String id)
      throws VimDriverException {
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    /* I suppose that checking for the result waits also for the effectivness of the operation */
    log.info(
        "Deleting VM with id "
            + id
            + ", result is: "
            + os.compute().servers().delete(id).isSuccess());
  }

  @Override
  public Network createNetwork(BaseVimInstance vimInstance, BaseNetwork network) throws VimDriverException {

    Network osNetwork = (Network) network;
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    org.openstack4j.model.network.Network network4j =
        os.networking()
            .network()
            .create(
                Builders.network()
                    .name(osNetwork .getName())
                    .adminStateUp(true)
                    .isShared(osNetwork .getExtShared())
                    .build());
    return Utils.getNetwork(network4j);
  }

  private void attachToRouter(OSClient os, String subnetExtId, BaseVimInstance vimInstance)
      throws VimDriverException {
    OpenstackVimInstance openstackVimInstance = (OpenstackVimInstance) vimInstance;
    List<? extends Router> tmpRouters = os.networking().router().list();
    List<Router> routers = new ArrayList<>();
    for (Router router : tmpRouters) {
      if ((isV3API(vimInstance) && router.getTenantId().equals(openstackVimInstance.getTenant())
          || (!isV3API(vimInstance)
              && router.getTenantId().equals(getTenantFromName(os, openstackVimInstance.getTenant()))))) {
        routers.add(router);
      }
    }
    RouterInterface iface;
    if (!routers.isEmpty()) {
      Router router = routers.get(0);
      iface =
          os.networking()
              .router()
              .attachInterface(router.getId(), AttachInterfaceType.SUBNET, subnetExtId);
    } else {
      Router router = createRouter(os, vimInstance);
      iface =
          os.networking()
              .router()
              .attachInterface(router.getId(), AttachInterfaceType.SUBNET, subnetExtId);
    }
    if (iface == null) {
      throw new VimDriverException("Not Able to attach to router the new subnet");
    }
  }

  private Router createRouter(OSClient os, BaseVimInstance vimInstance) throws VimDriverException {
    log.info("Create Router on " + vimInstance.getName());
    return os.networking()
        .router()
        .create(
            Builders.router()
                .name("openbaton-router")
                .adminStateUp(true)
                .externalGateway(getExternalNet(vimInstance).getExtId())
                .build());
  }

  private Network getExternalNet(BaseVimInstance vimInstance) throws VimDriverException {
    for (BaseNetwork net : listNetworks(vimInstance)) {

      if (((Network)net).getExternal()) {
        return ((Network)net);
      }
    }
    throw new VimDriverException("No External Network found! please add one");
  }

  @Override
  public DeploymentFlavour addFlavor(BaseVimInstance vimInstance, DeploymentFlavour deploymentFlavour)
      throws VimDriverException {
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    //TODO add missing parameter to deployment flavor, hopefully fixed with etsi v2.1.1
    Flavor flavor =
        os.compute()
            .flavors()
            .create(
                Builders.flavor()
                    .name(deploymentFlavour.getFlavour_key())
                    .disk(deploymentFlavour.getDisk())
                    .isPublic(false)
                    .ram(deploymentFlavour.getRam())
                    .vcpus(deploymentFlavour.getVcpus())
                    .build());

    return Utils.getFlavor(flavor);
  }

  @Override
  public NFVImage addImage(final BaseVimInstance vimInstance, BaseNfvImage image, String image_url)
      throws VimDriverException {
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    final Payload<URL> payload;
    try {
      payload = Payloads.create(new URL(image_url));
    } catch (MalformedURLException e) {
      e.printStackTrace();
      throw new VimDriverException(e.getMessage(), e);
    }
    NFVImage osImage = (NFVImage) image;
    final org.openstack4j.model.image.v2.Image imageV2 =
        os.imagesV2()
            .create(
                Builders.imageV2()
                    .name(osImage.getName())
                    .containerFormat(
                        org.openstack4j.model.image.v2.ContainerFormat.value(
                            osImage.getContainerFormat().toUpperCase()))
                    .visibility(
                        osImage.isPublic()
                            ? org.openstack4j.model.image.v2.Image.ImageVisibility.PUBLIC
                            : org.openstack4j.model.image.v2.Image.ImageVisibility.PRIVATE)
                    .diskFormat(
                        org.openstack4j.model.image.v2.DiskFormat.value(
                            osImage.getDiskFormat().toUpperCase()))
                    .minDisk(osImage.getMinDiskSpace())
                    .minRam(osImage.getMinRam())
                    .build());

    Thread t =
        new Thread(
            () -> {
              OSClient os1;
              try {
                os1 = authenticate((OpenstackVimInstance) vimInstance);
                ActionResponse upload = os1.imagesV2().upload(imageV2.getId(), payload, imageV2);
                if (!upload.isSuccess()) {
                  throw new VimDriverException("Error uploading image: " + upload.getFault());
                }
              } catch (VimDriverException e) {
                e.printStackTrace();
              }
            });

    t.start();
    return Utils.getImageV2(imageV2);
  }

  @Override
  public NFVImage updateImage(BaseVimInstance vimInstance, BaseNfvImage image) throws VimDriverException {
    return null;
  }

  @Override
  public NFVImage copyImage(BaseVimInstance vimInstance, BaseNfvImage  image, byte[] imageFile)
      throws VimDriverException {
    return null;
  }

  @Override
  public boolean deleteImage(BaseVimInstance vimInstance, BaseNfvImage image) throws VimDriverException {
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    return os.images().delete(image.getExtId()).isSuccess();
  }

  @Override
  public DeploymentFlavour updateFlavor(
      BaseVimInstance vimInstance, DeploymentFlavour deploymentFlavour) throws VimDriverException {
    return null;
  }

  @Override
  public boolean deleteFlavor(BaseVimInstance vimInstance, String extId) throws VimDriverException {
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    return os.compute().flavors().delete(extId).isSuccess();
  }

  @Override
  public Subnet createSubnet(BaseVimInstance vimInstance, BaseNetwork createdNetwork, Subnet subnet)
      throws VimDriverException {
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    org.openstack4j.model.network.Subnet subnet4j =
        os.networking()
            .subnet()
            .create(
                Builders.subnet()
                    .name(subnet.getName())
                    .networkId(createdNetwork.getExtId())
                    .ipVersion(IPVersionType.V4)
                    .cidr(subnet.getCidr())
                    .addDNSNameServer(properties.getProperty("openstack4j.dns.ip", "8.8.8.8"))
                    .enableDHCP(true)
                    .gateway(subnet.getGatewayIp())
                    .build());

    Subnet sn = Utils.getSubnet(subnet4j);
    try {
      attachToRouter(os, sn.getExtId(), vimInstance);
    } catch (VimDriverException e) {
      log.error(e.getMessage());
    }
    return sn;
  }

  //TODO need to chage byte[] to stream, at least...
  @Override
  public NFVImage addImage(BaseVimInstance vimInstance, BaseNfvImage image, byte[] imageFile)
      throws VimDriverException {
    throw new UnsupportedOperationException();
  }

  @Override
  public Network updateNetwork(BaseVimInstance vimInstance, BaseNetwork network) throws VimDriverException {
    return null;
  }

  @Override
  public Subnet updateSubnet(BaseVimInstance vimInstance, BaseNetwork updatedNetwork, Subnet subnet)
      throws VimDriverException {
    return null;
  }

  @Override
  public List<String> getSubnetsExtIds(BaseVimInstance vimInstance, String network_extId)
      throws VimDriverException {
    return null;
  }

  @Override
  public boolean deleteSubnet(BaseVimInstance vimInstance, String existingSubnetExtId)
      throws VimDriverException {
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    return os.networking().subnet().delete(existingSubnetExtId).isSuccess();
  }

  @Override
  public boolean deleteNetwork(BaseVimInstance vimInstance, String extId) throws VimDriverException {
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    return os.networking().network().delete(extId).isSuccess();
  }

  @Override
  public Network getNetworkById(BaseVimInstance vimInstance, String id) throws VimDriverException {
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    return Utils.getNetwork(os.networking().network().get(id));
  }

  @Override
  public Quota getQuota(BaseVimInstance vimInstance) throws VimDriverException {
    OpenstackVimInstance openstackVimInstance = (OpenstackVimInstance) vimInstance;
    OSClient os = this.authenticate(openstackVimInstance);
    QuotaSet qs = os.compute().quotaSets().get(openstackVimInstance.getTenant());
    NetQuota netQuota = os.networking().quotas().get(openstackVimInstance.getTenant());
    return Utils.getQuota(qs, netQuota, openstackVimInstance.getTenant());
  }

  @Override
  public String getType(BaseVimInstance vimInstance) throws VimDriverException {
    return "openstack";
  }
}
