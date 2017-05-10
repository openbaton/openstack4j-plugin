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
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.commons.codec.binary.Base64;
import org.openbaton.catalogue.mano.common.DeploymentFlavour;
import org.openbaton.catalogue.mano.descriptor.VNFDConnectionPoint;
import org.openbaton.catalogue.nfvo.NFVImage;
import org.openbaton.catalogue.nfvo.Network;
import org.openbaton.catalogue.nfvo.Quota;
import org.openbaton.catalogue.nfvo.Server;
import org.openbaton.catalogue.nfvo.Subnet;
import org.openbaton.catalogue.nfvo.VimInstance;
import org.openbaton.catalogue.security.Key;
import org.openbaton.exceptions.NotFoundException;
import org.openbaton.exceptions.VimDriverException;
import org.openbaton.exceptions.VimException;
import org.openbaton.plugin.PluginStarter;
import org.openbaton.vim.drivers.interfaces.VimDriver;
import org.openstack4j.api.Builders;
import org.openstack4j.api.OSClient;
import org.openstack4j.api.exceptions.AuthenticationException;
import org.openstack4j.model.common.ActionResponse;
import org.openstack4j.model.common.Identifier;
import org.openstack4j.model.common.Payload;
import org.openstack4j.model.common.Payloads;
import org.openstack4j.model.compute.Address;
import org.openstack4j.model.compute.Flavor;
import org.openstack4j.model.compute.QuotaSet;
import org.openstack4j.model.compute.ServerCreate;
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

/** Created by gca on 10/01/17. */
public class OpenStack4JDriver extends VimDriver {

  private Logger log = LoggerFactory.getLogger(OpenStack4JDriver.class);
  private static Lock lock;

  public OpenStack4JDriver() {
    super();
    init();
  }

  public void init() {
    String sslChecksDisabled = properties.getProperty("disable-ssl-certificate-checks", "false");
    log.debug("Disable SSL certificate checks: {}", sslChecksDisabled);
    OpenStack4JDriver.lock = new ReentrantLock();
  }

  public OSClient authenticate(VimInstance vimInstance) throws VimDriverException {

    OSClient os;
    try {
      if (isV3API(vimInstance)) {

        Identifier domain = Identifier.byName("Default");
        Identifier project = Identifier.byId(vimInstance.getTenant());
        log.trace("Domain id: " + domain.getId());
        log.trace("Project id: " + project.getId());

        os =
            OSFactory.builderV3()
                .endpoint(vimInstance.getAuthUrl())
                .scopeToProject(project)
                .credentials(vimInstance.getUsername(), vimInstance.getPassword(), domain)
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

  private boolean isV3API(VimInstance vimInstance) {
    return vimInstance.getAuthUrl().endsWith("/v3") || vimInstance.getAuthUrl().endsWith("/v3.0");
  }

  public static void main(String[] args)
      throws NoSuchMethodException, IOException, InstantiationException, TimeoutException,
          IllegalAccessException, InvocationTargetException {
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
      VimInstance vimInstance,
      String name,
      String image,
      String flavor,
      String keypair,
      Set<VNFDConnectionPoint> network,
      Set<String> secGroup,
      String userData)
      throws VimDriverException {
    Server server = null;
    try {
      OSClient os = this.authenticate(vimInstance);
      List<String> networks = getNetworkIdsFromNames(vimInstance, network);

      String imageId = getImageIdFromName(vimInstance, image);
      log.debug("imageId: " + imageId);
      org.openstack4j.model.image.Image imageFromVim = os.images().get(imageId);
      log.debug("Image received from VIM: " + imageFromVim);
      if (imageFromVim == null) {
        throw new VimException("Not found image " + image + " on VIM " + vimInstance.getName());
      } else if (imageFromVim.getStatus() == null
          || imageFromVim.getStatus() != (org.openstack4j.model.image.Image.Status.ACTIVE)) {
        throw new VimException("Image " + image + " is not yet in active. Try again later...");
      }
      Flavor flavor4j = getFlavorFromName(vimInstance, flavor);
      flavor = flavor4j.getId();
      // temporary workaround for getting first security group as it seems not supported adding multiple security groups
      ServerCreate sc;
      if (keypair == null || keypair.equals("")) {
        sc =
            Builders.server()
                .name(name)
                .flavor(flavor)
                .image(imageId)
                .networks(networks)
                .userData(new String(Base64.encodeBase64(userData.getBytes())))
                .build();
      } else {
        sc =
            Builders.server()
                .name(name)
                .flavor(flavor)
                .image(imageId)
                .keypairName(keypair)
                .networks(networks)
                .userData(new String(Base64.encodeBase64(userData.getBytes())))
                .build();
      }

      for (String sg : secGroup) {
        sc.addSecurityGroup(sg);
      }

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
              + network);
      org.openstack4j.model.compute.Server server4j = os.compute().servers().boot(sc);
      server = Utils.getServer(server4j);
    } catch (Exception e) {
      log.error(e.getMessage(), e);
      VimDriverException vimDriverException = new VimDriverException(e.getMessage());
      if (server != null) vimDriverException.setServer(server);
      throw vimDriverException;
    }
    return server;
  }

  private Flavor getFlavorFromName(VimInstance vimInstance, String flavor)
      throws VimDriverException {
    OSClient os = authenticate(vimInstance);
    for (Flavor flavor4j : os.compute().flavors().list()) {
      if (flavor4j.getName().equals(flavor) || flavor4j.getId().equals(flavor)) {
        return flavor4j;
      }
    }
    throw new VimDriverException("Flavor with name " + flavor + " was not found");
  }

  private List<String> getNetworkIdsFromNames(
      VimInstance vimInstance, Set<VNFDConnectionPoint> networks) throws VimDriverException {
    OSClient os = authenticate(vimInstance);
    List<String> res = new ArrayList<>();

    List<? extends org.openstack4j.model.network.Network> networkList =
        os.networking().network().list();

    Collections.sort(networkList, new NetworkComparator());

    Gson gson = new Gson();
    String oldVNFDCP = gson.toJson(networks);
    Set<VNFDConnectionPoint> newNetworks =
        gson.fromJson(oldVNFDCP, new TypeToken<Set<VNFDConnectionPoint>>() {}.getType());

    VNFDConnectionPoint[] vnfdConnectionPoints = newNetworks.toArray(new VNFDConnectionPoint[0]);
    Arrays.sort(
        vnfdConnectionPoints,
        new Comparator<VNFDConnectionPoint>() {
          @Override
          public int compare(VNFDConnectionPoint o1, VNFDConnectionPoint o2) {
            return o1.getInterfaceId() - o2.getInterfaceId();
          }
        });

    String tenantId =
        isV3API(vimInstance)
            ? vimInstance.getTenant()
            : getTenantFromName(os, vimInstance.getTenant());
    for (VNFDConnectionPoint vnfdConnectionPoint : vnfdConnectionPoints) {
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
    log.debug("result " + res);
    return res;
  }

  private String getImageIdFromName(VimInstance vimInstance, String imageName)
      throws VimDriverException {
    log.info("Getting image id of " + imageName + " on " + vimInstance.getName());
    OSClient os = this.authenticate(vimInstance);
    for (NFVImage image4j : this.listImages(vimInstance)) {
      if (image4j.getName().equals(imageName) || image4j.getExtId().equals(imageName))
        return image4j.getExtId();
    }
    throw new VimDriverException("Not found image '" + imageName + "' on " + vimInstance.getName());
  }

  private List<NetFloatingIP> listFloatingIps(OSClient os, VimInstance vimInstance)
      throws VimDriverException {
    //    OSClient os = this.authenticate(vimInstance);
    log.info("Listing all floating IPs of " + vimInstance.getName());
    List<? extends NetFloatingIP> floatingIPs = os.networking().floatingip().list();

    List<NetFloatingIP> res = new ArrayList<>();
    for (NetFloatingIP floatingIP : floatingIPs) {
      if (isV3API(vimInstance) && floatingIP.getTenantId().equals(vimInstance.getTenant())
          || (!isV3API(vimInstance)
              && floatingIP.getTenantId().equals(getTenantFromName(os, vimInstance.getTenant()))))
        if (floatingIP.getFixedIpAddress() == null || floatingIP.getFixedIpAddress().equals("")) {
          res.add(floatingIP);
        }
    }
    return res;
  }

  //  private Server getNFVServer(org.openstack4j.model.compute.Server server) {
  //    Server nfvServer = new Server();
  //    nfvServer.setExtId(server.getId());
  //    nfvServer.setName(server.getName());
  //    nfvServer.setStatus(server.getStatus().toString());
  //    HashMap<String, List<String>> privateIpMap = new HashMap<>();
  //    HashMap<String, String> floatingIpMap = new HashMap<>();
  //    server.getIps();
  //
  //    for(nfvServer)
  //      for (String key : server.getAddresses().keys()) {
  //        List<String> ips = new ArrayList<String>();
  //        for (Address address : jcloudsServer.getAddresses().get(key)) {
  //          String ip = address.getAddr();
  //          if (allFloatingIps.contains(ip)) {
  //            floatingIpMap.put(key, ip);
  //          } else {
  //            ips.add(ip);
  //          }
  //        }
  //        privateIpMap.put(key, ips);
  //      }
  //
  //
  //    return nfvServer;
  //  }

  @Override
  public List<NFVImage> listImages(VimInstance vimInstance) throws VimDriverException {
    try {
      OSClient os = this.authenticate(vimInstance);
      Map<String, String> map = new HashMap<>();
      map.put("limit", "100");
      List<? extends Image> images = os.images().list(map);
      List<NFVImage> nfvImages = new ArrayList<>();
      for (Image image : images) {
        nfvImages.add(Utils.getImage(image));
      }
      log.info(
          "Listed images for VimInstance with name: "
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
  public List<Server> listServer(VimInstance vimInstance) throws VimDriverException {

    List<Server> obServers = new ArrayList<>();
    try {
      OSClient os = this.authenticate(vimInstance);

      List<? extends org.openstack4j.model.compute.Server> servers = os.compute().servers().list();
      for (org.openstack4j.model.compute.Server srv : servers) {
        if ((isV3API(vimInstance) && srv.getTenantId().equals(vimInstance.getTenant())
            || (!isV3API(vimInstance)
                && srv.getTenantId().equals(getTenantFromName(os, vimInstance.getTenant())))))
          obServers.add(Utils.getServer(srv));
      }
    } catch (Exception e) {
      log.error(e.getMessage(), e);
      throw new VimDriverException(e.getMessage());
    }
    return obServers;
  }

  @Override
  public List<Network> listNetworks(VimInstance vimInstance) throws VimDriverException {
    try {
      OSClient os = this.authenticate(vimInstance);
      List<? extends org.openstack4j.model.network.Network> networks =
          os.networking().network().list();
      log.info("Received all networks: " + networks);
      List<Network> nfvNetworks = new ArrayList<>();
      for (org.openstack4j.model.network.Network network : networks) {
        log.trace("Check network: " + network);
        log.trace(
            "Check if network belongs to tenant -> "
                + network.getTenantId()
                + "=="
                + getTenantFromName(os, vimInstance.getTenant()));
        if ((network.isRouterExternal() || network.isShared())
            || (isV3API(vimInstance) && network.getTenantId().equals(vimInstance.getTenant())
                || (!isV3API(vimInstance)
                    && network
                        .getTenantId()
                        .equals(getTenantFromName(os, vimInstance.getTenant()))))) {
          Network nfvNetwork = Utils.getNetwork(network);
          if (network.getSubnets() != null && !network.getSubnets().isEmpty()) {
            for (String subnetId : network.getSubnets()) {
              Subnet subnet = getSubnetById(os, vimInstance, subnetId);
              if (subnet == null) continue;
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

  private Subnet getSubnetById(OSClient os, VimInstance vimInstance, String subnetId)
      throws VimDriverException, NotFoundException {
    log.debug(
        "Getting Subnet with extId: "
            + subnetId
            + " from VimInstance with name: "
            + vimInstance.getName());
    try {
      org.openstack4j.model.network.Subnet subnet = os.networking().subnet().get(subnetId);
      log.debug("Found subnet: " + subnet);
      if (subnet != null) return Utils.getSubnet(subnet);
      else return null;
    } catch (Exception e) {
      log.error(e.getMessage(), e);
      throw new VimDriverException(e.getMessage());
    }
  }

  @Override
  public List<DeploymentFlavour> listFlavors(VimInstance vimInstance) throws VimDriverException {
    List<DeploymentFlavour> deploymentFlavours = new ArrayList<>();
    try {
      OSClient os = this.authenticate(vimInstance);
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
  public Server launchInstanceAndWait(
      VimInstance vimInstance,
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

    boolean bootCompleted = false;
    if (keys != null && !keys.isEmpty()) {
      userdata = addKeysToUserData(userdata, keys);
    }
    if (userdata == null) userdata = "";
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
        server.setFloatingIps(new HashMap<String, String>());
      }
      if (floatingIps != null && floatingIps.size() > 0) {
        OpenStack4JDriver.lock.lock(); // TODO chooseFloating ip is lock but association is parallel
        log.debug("Assigning FloatingIPs to VM with hostname: " + name);
        log.debug("FloatingIPs are: " + floatingIps);
        int freeIps = listFloatingIps(this.authenticate(vimInstance), vimInstance).size();
        int ipsNeeded = floatingIps.size();
        if (freeIps < ipsNeeded) {
          log.error(
              "Insufficient number of ips allocated to tenant, will try to allocate more ips from pool");
          log.debug("Getting the pool name of a floating ip pool");
          String pool_name = getIpPoolName(vimInstance);
          allocateFloatingIps(vimInstance, pool_name, ipsNeeded - freeIps);
        }
        if (listFloatingIps(this.authenticate(vimInstance), vimInstance).size()
            >= floatingIps.size()) {
          for (Map.Entry<String, String> fip : floatingIps.entrySet()) {
            server
                .getFloatingIps()
                .put(fip.getKey(), associateFloatingIpToNetwork(vimInstance, server4j, fip));
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
          if (server != null) exception.setServer(server);
          throw exception;
        }
        OpenStack4JDriver.lock.unlock();
      }
    } catch (Exception e) {
      log.error(e.getMessage());
      VimDriverException exception = new VimDriverException(e.getMessage(), e);
      if (server != null) exception.setServer(server);
      throw exception;
    }
    log.info("Finish association of FIPs if any for server: " + server);
    return server;
  }

  private org.openstack4j.model.compute.Server getServerById(VimInstance vimInstance, String extId)
      throws VimDriverException {
    OSClient os = authenticate(vimInstance);
    return os.compute().servers().get(extId);
  }

  private String associateFloatingIpToNetwork(
      VimInstance vimInstance,
      org.openstack4j.model.compute.Server server4j,
      Map.Entry<String, String> fip)
      throws VimDriverException {

    OSClient os = authenticate(vimInstance);

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

  private NetFloatingIP findFloatingIpId(OSClient os, String fipValue, VimInstance vimInstance)
      throws VimDriverException {
    if (fipValue.trim().equalsIgnoreCase("random") || fipValue.trim().equals(""))
      return listFloatingIps(os, vimInstance).get(0);
    for (NetFloatingIP floatingIP : os.networking().floatingip().list()) {
      if (floatingIP.getFloatingIpAddress().equalsIgnoreCase(fipValue)) {
        return floatingIP;
      }
    }
    throw new VimDriverException("Floating ip " + fipValue + " not found");
  }

  private void allocateFloatingIps(VimInstance vimInstance, String poolName, int numOfFip)
      throws VimDriverException {
    OSClient os = authenticate(vimInstance);
    for (int i = 0; i < numOfFip; i++) os.compute().floatingIps().allocateIP(poolName);
  }

  private String getIpPoolName(VimInstance vimInstance) throws VimDriverException {
    OSClient os = authenticate(vimInstance);
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
      VimInstance vimInstance,
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
    /** doing this for avoiding a serialization error of gson */
    Gson gson = new Gson();
    String oldKeys = gson.toJson(keys);
    Set<org.openbaton.catalogue.security.Key> keysSet =
        gson.fromJson(
            oldKeys, new TypeToken<Set<org.openbaton.catalogue.security.Key>>() {}.getType());

    for (org.openbaton.catalogue.security.Key key : keysSet) {
      log.debug("Adding key: " + key.getName());
      userData += "\techo \"" + key.getPublicKey() + "\" >> $x\n";
    }
    userData += "done\n";
    return userData;
  }

  @Override
  public void deleteServerByIdAndWait(VimInstance vimInstance, String id)
      throws VimDriverException {
    OSClient os = this.authenticate(vimInstance);
    /** I suppose that checking for the result waits also for the effectivness of the operation */
    log.info(
        "Deleting VM with id "
            + id
            + ", result is: "
            + os.compute().servers().delete(id).isSuccess());
  }

  @Override
  public Network createNetwork(VimInstance vimInstance, Network network) throws VimDriverException {

    OSClient os = this.authenticate(vimInstance);
    org.openstack4j.model.network.Network network4j =
        os.networking()
            .network()
            .create(
                Builders.network()
                    .name(network.getName())
                    .adminStateUp(true)
                    .isShared(network.getShared())
                    .build());
    //    for (Subnet subnet : network.getSubnets()) {
    //      Subnet sn = createSubnet(vimInstance, res, subnet);
    //      res.getSubnets().add(sn);
    //
    //    }
    return Utils.getNetwork(network4j);
  }

  private void attachToRouter(OSClient os, String subnetExtId, VimInstance vimInstance)
      throws VimDriverException {
    List<? extends Router> tmpRouters = os.networking().router().list();
    List<Router> routers = new ArrayList<>();
    for (Router router : tmpRouters)
      if ((isV3API(vimInstance) && router.getTenantId().equals(vimInstance.getTenant())
          || (!isV3API(vimInstance)
              && router.getTenantId().equals(getTenantFromName(os, vimInstance.getTenant())))))
        routers.add(router);
    RouterInterface iface;
    if (routers != null && !routers.isEmpty()) {
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
    if (iface == null) throw new VimDriverException("Not Able to attach to router the new subnet");
  }

  private Router createRouter(OSClient os, VimInstance vimInstance) throws VimDriverException {
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

  private Network getExternalNet(VimInstance vimInstance) throws VimDriverException {
    for (Network net : listNetworks(vimInstance)) {
      if (net.getExternal()) {
        return net;
      }
    }
    throw new VimDriverException("No External Network found! please add one");
  }

  @Override
  public DeploymentFlavour addFlavor(VimInstance vimInstance, DeploymentFlavour deploymentFlavour)
      throws VimDriverException {
    OSClient os = this.authenticate(vimInstance);
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
  public NFVImage addImage(final VimInstance vimInstance, NFVImage image, String image_url)
      throws VimDriverException {
    OSClient os = this.authenticate(vimInstance);
    final Payload<URL> payload;
    try {
      payload = Payloads.create(new URL(image_url));
    } catch (MalformedURLException e) {
      e.printStackTrace();
      throw new VimDriverException(e.getMessage(), e);
    }
    //    Image image4j =
    //        os.images()
    //            .create(
    //                Builders.image()
    //                    .name(image.getName())
    //                    .isPublic(image.isPublic())
    //                    .containerFormat(
    //                        ContainerFormat.value(image.getContainerFormat().toUpperCase()))
    //                    .diskFormat(DiskFormat.value(image.getDiskFormat().toUpperCase()))
    //                    .minDisk(image.getMinDiskSpace())
    //                    .minRam(image.getMinRam())
    //                    .build(),
    //                payload);
    //    return Utils.getImage(image4j);

    final org.openstack4j.model.image.v2.Image imageV2 =
        os.imagesV2()
            .create(
                Builders.imageV2()
                    .name(image.getName())
                    .containerFormat(
                        org.openstack4j.model.image.v2.ContainerFormat.value(
                            image.getContainerFormat().toUpperCase()))
                    .visibility(
                        image.isPublic()
                            ? org.openstack4j.model.image.v2.Image.ImageVisibility.PUBLIC
                            : org.openstack4j.model.image.v2.Image.ImageVisibility.PRIVATE)
                    .diskFormat(
                        org.openstack4j.model.image.v2.DiskFormat.value(
                            image.getDiskFormat().toUpperCase()))
                    .minDisk((int) image.getMinDiskSpace())
                    .minRam((int) image.getMinRam())
                    .build());

    Thread t =
        new Thread(
            new Runnable() {
              @Override
              public void run() {
                OSClient os = null;
                try {
                  os = authenticate(vimInstance);
                } catch (VimDriverException e) {
                  e.printStackTrace();
                }
                ActionResponse upload = os.imagesV2().upload(imageV2.getId(), payload, imageV2);
              }
            });

    t.start();
    return Utils.getImageV2(imageV2);
  }

  @Override
  public NFVImage updateImage(VimInstance vimInstance, NFVImage image) throws VimDriverException {
    return null;
  }

  @Override
  public NFVImage copyImage(VimInstance vimInstance, NFVImage image, byte[] imageFile)
      throws VimDriverException {
    return null;
  }

  @Override
  public boolean deleteImage(VimInstance vimInstance, NFVImage image) throws VimDriverException {
    OSClient os = this.authenticate(vimInstance);
    return os.images().delete(image.getExtId()).isSuccess();
  }

  @Override
  public DeploymentFlavour updateFlavor(
      VimInstance vimInstance, DeploymentFlavour deploymentFlavour) throws VimDriverException {
    return null;
  }

  @Override
  public boolean deleteFlavor(VimInstance vimInstance, String extId) throws VimDriverException {
    OSClient os = this.authenticate(vimInstance);
    return os.compute().flavors().delete(extId).isSuccess();
  }

  @Override
  public Subnet createSubnet(VimInstance vimInstance, Network createdNetwork, Subnet subnet)
      throws VimDriverException {
    OSClient os = this.authenticate(vimInstance);
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
  public NFVImage addImage(VimInstance vimInstance, NFVImage image, byte[] imageFile)
      throws VimDriverException {
    throw new UnsupportedOperationException();
  }

  @Override
  public Network updateNetwork(VimInstance vimInstance, Network network) throws VimDriverException {
    return null;
  }

  @Override
  public Subnet updateSubnet(VimInstance vimInstance, Network updatedNetwork, Subnet subnet)
      throws VimDriverException {
    return null;
  }

  @Override
  public List<String> getSubnetsExtIds(VimInstance vimInstance, String network_extId)
      throws VimDriverException {
    return null;
  }

  @Override
  public boolean deleteSubnet(VimInstance vimInstance, String existingSubnetExtId)
      throws VimDriverException {
    OSClient os = this.authenticate(vimInstance);
    return os.networking().subnet().delete(existingSubnetExtId).isSuccess();
  }

  @Override
  public boolean deleteNetwork(VimInstance vimInstance, String extId) throws VimDriverException {
    OSClient os = this.authenticate(vimInstance);
    return os.networking().network().delete(extId).isSuccess();
  }

  @Override
  public Network getNetworkById(VimInstance vimInstance, String id) throws VimDriverException {
    OSClient os = this.authenticate(vimInstance);
    return Utils.getNetwork(os.networking().network().get(id));
  }

  @Override
  public Quota getQuota(VimInstance vimInstance) throws VimDriverException {
    OSClient os = this.authenticate(vimInstance);
    QuotaSet qs = os.compute().quotaSets().get(vimInstance.getTenant());
    NetQuota netQuota = os.networking().quotas().get(vimInstance.getTenant());
    return Utils.getQuota(qs, netQuota, vimInstance.getTenant());
  }

  @Override
  public String getType(VimInstance vimInstance) throws VimDriverException {
    return "openstack4j";
  }

  private class NetworkComparator implements Comparator<org.openstack4j.model.network.Network> {
    @Override
    public int compare(
        org.openstack4j.model.network.Network network1,
        org.openstack4j.model.network.Network network2) {
      if (network1.getId() == network2.getId()) return 0;
      if (network1.getId() == null) return 1;
      if (network2.getId() == null) return -1;
      return network1.getId().compareTo(network2.getId());
    }
  }
}
