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

import org.openbaton.catalogue.mano.common.DeploymentFlavour;
import org.openbaton.catalogue.nfvo.NFVImage;
import org.openbaton.catalogue.nfvo.Network;
import org.openbaton.catalogue.nfvo.Quota;
import org.openbaton.catalogue.nfvo.Server;
import org.openbaton.catalogue.nfvo.Subnet;
import org.openbaton.catalogue.nfvo.VimInstance;
import org.openbaton.catalogue.security.Key;
import org.openbaton.exceptions.VimDriverException;
import org.openbaton.plugin.PluginStarter;
import org.openbaton.vim.drivers.interfaces.VimDriver;
import org.openstack4j.api.Builders;
import org.openstack4j.api.OSClient.OSClientV3;
import org.openstack4j.model.common.Identifier;
import org.openstack4j.model.compute.Flavor;
import org.openstack4j.model.image.Image;
import org.openstack4j.model.network.IPVersionType;
import org.openstack4j.openstack.OSFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeoutException;

/** Created by gca on 10/01/17. */
public class OpenStack4JDriver extends VimDriver {

  private static Logger log = LoggerFactory.getLogger(OpenStack4JDriver.class);

  Properties overrides;

  public OpenStack4JDriver() {
    super();
    init();
  }

  public void init() {
    overrides = new Properties();
    String sslChecksDisabled = properties.getProperty("disable-ssl-certificate-checks", "false");
    log.debug("Disable SSL certificate checks: {}", sslChecksDisabled);
    //        if (sslChecksDisabled.trim().equals("true")) {
    //            DisableSSLValidation.disableChecks();
    //        }
  }

  public OSClientV3 authenticate(VimInstance vimInstance) {
    return OSFactory.builderV3()
        .endpoint(vimInstance.getAuthUrl())
        .credentials(
            vimInstance.getUsername(), vimInstance.getPassword(), Identifier.byName("Default"))
        .scopeToProject(Identifier.byName(vimInstance.getTenant()))
        .authenticate();
  }

  public static void main(String[] args)
      throws NoSuchMethodException, IOException, InstantiationException, TimeoutException,
          IllegalAccessException, InvocationTargetException {
    if (args.length == 6) {
      PluginStarter.registerPlugin(
          OpenStack4JDriver.class,
          args[0],
          args[1],
          Integer.parseInt(args[2]),
          Integer.parseInt(args[3]),
          args[4],
          args[5]);
    } else if (args.length == 4) {
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
      Set<String> network,
      Set<String> secGroup,
      String userData)
      throws VimDriverException {
    return null;
  }

  @Override
  public List<NFVImage> listImages(VimInstance vimInstance) throws VimDriverException {
    try {
      OSClientV3 os = this.authenticate(vimInstance);
      List<? extends Image> images = os.images().list();
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
      OSClientV3 os = this.authenticate(vimInstance);

      List<? extends org.openstack4j.model.compute.Server> servers = os.compute().servers().list();
      for (org.openstack4j.model.compute.Server srv : servers) {

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
      OSClientV3 os = this.authenticate(vimInstance);
      List<? extends org.openstack4j.model.network.Network> networks =
          os.networking().network().list();
      List<Network> nfvNetworks = new ArrayList<>();
      for (org.openstack4j.model.network.Network network : networks) {
        Network nfvNetwork = Utils.getNetwork(network);
        for (String subnetId : network.getSubnets()) {
          nfvNetwork.getSubnets().add(getSubnetById(os, vimInstance, subnetId));
        }
      }
      return nfvNetworks;
    } catch (Exception e) {
      log.error(e.getMessage(), e);
      throw new VimDriverException(e.getMessage());
    }
  }

  private Subnet getSubnetById(OSClientV3 os, VimInstance vimInstance, String subnetId)
      throws VimDriverException {
    log.debug(
        "Getting Subnet with extId: "
            + subnetId
            + " from VimInstance with name: "
            + vimInstance.getName());
    try {
      org.openstack4j.model.network.Subnet subnet = os.networking().subnet().get(subnetId);
      return Utils.getSubnet(subnet);
    } catch (Exception e) {
      log.error(e.getMessage(), e);
      throw new VimDriverException(e.getMessage());
    }
  }

  @Override
  public List<DeploymentFlavour> listFlavors(VimInstance vimInstance) throws VimDriverException {
    List<DeploymentFlavour> deploymentFlavours = new ArrayList<>();
    try {
      OSClientV3 os = this.authenticate(vimInstance);
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
      String hostname,
      String image,
      String extId,
      String keyPair,
      Set<String> networks,
      Set<String> securityGroups,
      String s,
      Map<String, String> floatingIps,
      Set<Key> keys)
      throws VimDriverException {
    return null;
  }

  @Override
  public Server launchInstanceAndWait(
      VimInstance vimInstance,
      String hostname,
      String image,
      String extId,
      String keyPair,
      Set<String> networks,
      Set<String> securityGroups,
      String s)
      throws VimDriverException {
    return null;
  }

  @Override
  public void deleteServerByIdAndWait(VimInstance vimInstance, String id)
      throws VimDriverException {}

  @Override
  public Network createNetwork(VimInstance vimInstance, Network network) throws VimDriverException {

    OSClientV3 os = this.authenticate(vimInstance);
    org.openstack4j.model.network.Network network4j = Utils.createNetwork(network);
    os.networking().network().create(network4j);
    Network res = Utils.getNetwork(network4j);
    for (Subnet subnet : network.getSubnets()) {
      network.getSubnets().add(createSubnet(vimInstance, res, subnet));
    }
    return res;
  }

  @Override
  public DeploymentFlavour addFlavor(VimInstance vimInstance, DeploymentFlavour deploymentFlavour)
      throws VimDriverException {
    return null;
  }

  @Override
  public NFVImage addImage(VimInstance vimInstance, NFVImage image, byte[] imageFile)
      throws VimDriverException {
    return null;
  }

  @Override
  public NFVImage addImage(VimInstance vimInstance, NFVImage image, String image_url)
      throws VimDriverException {
    return null;
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
    return false;
  }

  @Override
  public DeploymentFlavour updateFlavor(
      VimInstance vimInstance, DeploymentFlavour deploymentFlavour) throws VimDriverException {
    return null;
  }

  @Override
  public boolean deleteFlavor(VimInstance vimInstance, String extId) throws VimDriverException {
    return false;
  }

  @Override
  public Subnet createSubnet(VimInstance vimInstance, Network createdNetwork, Subnet subnet)
      throws VimDriverException {
    OSClientV3 os = this.authenticate(vimInstance);
    org.openstack4j.model.network.Subnet subnet4j =
        os.networking()
            .subnet()
            .create(
                Builders.subnet()
                    .name(subnet.getName())
                    .networkId(subnet.getNetworkId())
                    .ipVersion(IPVersionType.V4)
                    .cidr(subnet.getCidr())
                    .addDNSNameServer(properties.getProperty("openstack4j.dns.ip", "8.8.8.8"))
                    .enableDHCP(true)
                    .gateway(subnet.getGatewayIp())
                    .build());
    return Utils.getSubnet(subnet4j);
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
    return false;
  }

  @Override
  public boolean deleteNetwork(VimInstance vimInstance, String extId) throws VimDriverException {
    OSClientV3 os = this.authenticate(vimInstance);
    return os.networking().network().delete(extId).isSuccess();
  }

  @Override
  public Network getNetworkById(VimInstance vimInstance, String id) throws VimDriverException {
    OSClientV3 os = this.authenticate(vimInstance);
    return Utils.getNetwork(os.networking().network().get(id));
  }

  @Override
  public Quota getQuota(VimInstance vimInstance) throws VimDriverException {
    return null;
  }

  @Override
  public String getType(VimInstance vimInstance) throws VimDriverException {
    return null;
  }
}
