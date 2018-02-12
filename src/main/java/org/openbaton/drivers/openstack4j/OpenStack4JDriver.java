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
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.stream.Collectors;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.openbaton.catalogue.keys.PopKeypair;
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
import org.openstack4j.model.compute.SecGroupExtension;
import org.openstack4j.model.compute.ServerCreate;
import org.openstack4j.model.compute.actions.RebuildOptions;
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
import org.openstack4j.model.network.Port;
import org.openstack4j.model.network.Router;
import org.openstack4j.model.network.RouterInterface;
import org.openstack4j.model.network.builder.PortBuilder;
import org.openstack4j.model.network.builder.SubnetBuilder;
import org.openstack4j.model.network.options.PortListOptions;
import org.openstack4j.openstack.OSFactory;
import org.openstack4j.openstack.networking.domain.NeutronFloatingIP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OpenStack4JDriver extends VimDriver {

  private Logger log = LoggerFactory.getLogger(OpenStack4JDriver.class);
  private static Lock lock;
  private String waitForVM;

  public OpenStack4JDriver() {
    super();
    init();
  }

  private void init() {
    log.debug("Properties are " + properties);
    waitForVM = properties.getProperty("wait-for-vm", "5000");
    OpenStack4JDriver.lock = new ReentrantLock();
  }

  public OSClient authenticate(OpenstackVimInstance vimInstance) throws VimDriverException {

    OSClient os;
    Config cfg = Config.DEFAULT;
    cfg =
        cfg.withConnectionTimeout(
            Integer.parseInt(properties.getProperty("connection-timeout", "10000")));

    // Add the certificate given in the VIM to the keystore used by the OSClient
    if (vimInstance.getTrustedCertificate() != null
        && !vimInstance.getTrustedCertificate().equals("")) {
      log.debug("Certificate is provided in VIM " + vimInstance.getName());
      InputStream certificateInputStream = null;
      try {
        certificateInputStream =
            new ByteArrayInputStream(vimInstance.getTrustedCertificate().getBytes());
      } catch (Exception e) {
        log.error("Not able to generate InputStream from provided certificate field.");
        throw new VimDriverException(
            "Not able to generate InputStream from provided certificate field.", e);
      }
      try {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        log.debug("Try to generate certificate from InputStream.");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(certificateInputStream);
        TrustManagerFactory tmf =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null);
        String alias = cert.getSubjectX500Principal().getName();
        log.debug("Adding entry for certificate with alias " + alias + " to the KeyStore.");
        keyStore.setCertificateEntry(alias, cert);
        tmf.init(keyStore);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        cfg.withSSLContext(sslContext);
        log.debug("Added SSLContext with the trusted certificate to the OSClient configuration.");
      } catch (Exception e) {
        log.error(
            "Exception while adding the certificate in the OpenStack VIM "
                + vimInstance.getName()
                + "to the Java Key Store.");
        throw new VimDriverException(
            "Exception while adding the certificate in the OpenStack VIM "
                + vimInstance.getName()
                + " to the Java Key Store.",
            e);
      } finally {
        IOUtils.closeQuietly(certificateInputStream);
      }
    }

    try {
      if (isV3API(vimInstance)) {

        Identifier domain =
            vimInstance.getDomain() == null || vimInstance.getDomain().equals("")
                ? Identifier.byName("Default")
                : Identifier.byName(vimInstance.getDomain());
        Identifier project = Identifier.byId(vimInstance.getTenant());

        log.trace(
            "Authenticate method with domain id: "
                + domain.getId()
                + " and project id "
                + project.getId());

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
                    + "'. Using the default one...");
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
                    + "'. Using the default one...");
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
    return vimInstance.getAuthUrl().endsWith("/v3")
        || vimInstance.getAuthUrl().endsWith("/v3/")
        || vimInstance.getAuthUrl().endsWith("/v3.0");
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

  private void checkImageStatus(
      OSClient os, OpenstackVimInstance openstackVimInstance, String imageId, String imageName)
      throws VimException {

    log.debug("Retrieved imageId(" + imageId + ") from image with name " + imageName);
    org.openstack4j.model.image.Image imageFromVim = os.images().get(imageId);
    log.trace(
        "Retrieved image object from OpenStack: "
            + new GsonBuilder().setPrettyPrinting().create().toJson(imageFromVim));
    if (imageFromVim == null) {
      throw new VimException(
          "Not found image (name: " + imageName + ") on PoP " + openstackVimInstance.getName());
    }
    //GlanceV2 attempt
    else if (imageFromVim.getId() == null) {
      //When glanceV2 is exposed but you do a request to glanceV1 you get an ImageV1 object with all attributes equals
      //to null and status UNRECOGNIZED, hence we try to make a request to glanceV2
      org.openstack4j.model.image.v2.Image imageV2FromVim = os.imagesV2().get(imageId);
      log.trace(
          "Retrieved imageV2 object from OpenStack: "
              + new GsonBuilder().setPrettyPrinting().create().toJson(imageV2FromVim));
      if (imageV2FromVim == null) {
        throw new VimException(
            "Not found image (name: " + imageName + ") on PoP " + openstackVimInstance.getName());
      } else if (imageV2FromVim.getStatus() == null
          || imageV2FromVim.getStatus()
              != (org.openstack4j.model.image.v2.Image.ImageStatus.ACTIVE)) {
        throw new VimException(
            "Image (name: " + imageName + ") is not yet in active. Try again later...");
      }
    } else if (imageFromVim.getStatus() == null
        || imageFromVim.getStatus() != (org.openstack4j.model.image.Image.Status.ACTIVE)) {
      throw new VimException(
          "Image (name: " + imageName + ") is not yet in active. Try again later...");
    }
  }

  private Server launchInstance(
      OSClient os,
      OpenstackVimInstance openstackVimInstance,
      String name,
      String image,
      String flavor,
      String keypair,
      Set<VNFDConnectionPoint> vnfdConnectionPoints,
      Set<String> secGroup,
      String userData)
      throws VimDriverException {
    Server server;
    List<VNFDConnectionPoint> vnfdcps = new ArrayList<>(vnfdConnectionPoints);
    try {

      vnfdcps.sort(Comparator.comparing(VNFDConnectionPoint::getInterfaceId));

      String imageId = getImageIdFromName(openstackVimInstance, image);

      checkImageStatus(os, openstackVimInstance, imageId, image);

      Flavor flavor4j = getFlavorFromName(openstackVimInstance, flavor);
      flavor = flavor4j.getId();
      Optional<? extends AvailabilityZone> availabilityZone = getZone(os, openstackVimInstance);
      ServerCreate sc;
      // name, flavor, imageId, user-data and network are mandatory
      ServerCreateBuilder serverCreateBuilder =
          Builders.server()
              .name(name)
              .flavor(flavor)
              .image(imageId)
              .userData(new String(Base64.encodeBase64(userData.getBytes())));

      // check if keypair is not null and is not equal empty string
      if (keypair != null && !keypair.equals("")) {
        if (openstackVimInstance.getKeys().stream().noneMatch(k -> k.getName().equals(keypair))) {
          throw new VimDriverException(String.format("Keypair %s not found!", keypair));
        }
        serverCreateBuilder.keypairName(keypair);
      }

      availabilityZone.ifPresent(zone -> serverCreateBuilder.availabilityZone(zone.getZoneName()));

      // temporary workaround for getting first security group as it seems not supported adding multiple security groups

      os.compute()
          .securityGroups()
          .list()
          .stream()
          .filter(sg -> secGroup.contains(sg.getName()))
          .forEach(sg -> serverCreateBuilder.addSecurityGroup(sg.getName()));

      // creating ServerCreate object
      sc = serverCreateBuilder.build();

      for (VNFDConnectionPoint vnfdConnectionPoint : vnfdcps) {
        String openstackNetId = vnfdConnectionPoint.getVirtual_link_reference_id();
        Optional<? extends org.openstack4j.model.network.Network> networkByName = Optional.empty();
        if (openstackNetId == null) {
          networkByName =
              getNetworkByNameAndTenantId(
                  os,
                  vnfdConnectionPoint.getVirtual_link_reference(),
                  getTenantId(openstackVimInstance, os));
          if (networkByName.isPresent()) openstackNetId = networkByName.get().getId();
          else
            throw new VimDriverException(
                String.format(
                    "Not found network with name %s in tenant with id %s",
                    vnfdConnectionPoint.getVirtual_link_reference(),
                    getTenantId(openstackVimInstance, os)));
        }
        // create a port
        PortBuilder portBuilder = null;
        if (vnfdConnectionPoint.getFixedIp() != null
            && !vnfdConnectionPoint.getFixedIp().equals("")) {

          // get the subnet associated with the network
          List<String> subnets;
          if (networkByName.isPresent()) {
            subnets = networkByName.get().getSubnets();
          } else {
            org.openstack4j.model.network.Network network =
                os.networking().network().get(openstackNetId);
            subnets = network.getSubnets();
          }

          if (null == subnets) {
            throw new VimDriverException(
                String.format("Cannot find subnets of network with id %s", openstackNetId));
          }

          org.openstack4j.model.network.Subnet subnet = null;
          for (String subnetId : subnets) {
            subnet = os.networking().subnet().get(subnetId);
            SubnetUtils utils = new SubnetUtils(subnet.getCidr());
            if (utils.getInfo().isInRange(vnfdConnectionPoint.getFixedIp())) {
              break;
            }
            subnet = null;
          }

          if (null == subnet) {
            throw new VimDriverException(
                String.format(
                    "The fixed ip %s is not in the range of any of the subnets"
                        + " associated with the network with id %s",
                    vnfdConnectionPoint.getFixedIp(), openstackNetId));
          }

          portBuilder =
              Builders.port()
                  .name(buildPortName(vnfdConnectionPoint))
                  .networkId(openstackNetId)
                  .fixedIp(vnfdConnectionPoint.getFixedIp(), subnet.getId());

        } else {
          portBuilder =
              Builders.port().name(buildPortName(vnfdConnectionPoint)).networkId(openstackNetId);
        }

        List<? extends SecGroupExtension> osSecGroups = os.compute().securityGroups().list();
        for (SecGroupExtension sg : osSecGroups) {
          if (secGroup.contains(sg.getName())) {
            portBuilder = portBuilder.securityGroup(sg.getId());
          }
        }
        Port port = os.networking().port().create(portBuilder.build());
        if (null == port) {
          throw new VimDriverException(
              "Unable to create port on network with id " + openstackNetId);
        }
        log.debug("created port with id " + port.getId());

        sc.addNetworkPort(port.getId());
      }
      // creating ServerCreate object
      sc = serverCreateBuilder.build();

      List<String> netIds = new ArrayList<>();
      vnfdcps.forEach(v -> netIds.add(v.getVirtual_link_reference()));
      log.trace(
          "Keypair: "
              + keypair
              + ", SecGroup, "
              + secGroup
              + ", imageId: "
              + imageId
              + ", flavorId: "
              + flavor
              + ", networks: "
              + netIds);
      org.openstack4j.model.compute.Server server4j;
      if (vnfdcps.stream().anyMatch(this::allowsAllSourceAddresses)) {
        server4j =
            os.compute()
                .servers()
                .bootAndWaitActive(
                    sc, Integer.parseInt(properties.getProperty("maxActiveWaitTime", "300000")));
        os.networking()
            .port()
            .list()
            .stream()
            .filter(
                p -> {
                  for (Map.Entry<String, List<? extends Address>> e :
                      server4j.getAddresses().getAddresses().entrySet()) {
                    if (e.getValue()
                        .stream()
                        .anyMatch(a -> a.getMacAddr().equalsIgnoreCase(p.getMacAddress()))) {
                      if (vnfdcps
                          .stream()
                          .anyMatch(
                              cp ->
                                  allowsAllSourceAddresses(cp)
                                      && cp.getVirtual_link_reference().equals(e.getKey()))) {
                        return true;
                      }
                    }
                  }
                  return false;
                })
            .forEach(
                p ->
                    os.networking()
                        .port()
                        .update(
                            p.toBuilder()
                                .allowedAddressPair("0.0.0.0/0", p.getMacAddress())
                                .build()));
      } else {
        server4j = os.compute().servers().boot(sc);
      }

      server = Utils.getServer(server4j);
    } catch (Exception e) {
      log.error(e.getMessage(), e);

      // if any ports have been created delete them
      for (VNFDConnectionPoint vnfdConnectionPoint : vnfdcps) {
        PortListOptions options = PortListOptions.create().name(buildPortName(vnfdConnectionPoint));
        List<? extends Port> ports = os.networking().port().list(options);
        log.debug(
            "List of ports is " + new GsonBuilder().setPrettyPrinting().create().toJson(ports));
        for (Port port : ports) {
          os.networking().port().delete(port.getId());
        }
      }

      throw new VimDriverException(e.getMessage());
    }
    return server;
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
      String userData) {
    return null;
  }

  private String buildPortName(VNFDConnectionPoint vnfdConnectionPoint) {
    return "VNFD-" + vnfdConnectionPoint.getId();
  }

  private boolean allowsAllSourceAddresses(VNFDConnectionPoint cp) {
    return cp.getMetadata() != null
        && cp.getMetadata().containsKey("allowAllSourceAddresses")
        && cp.getMetadata().get("allowAllSourceAddresses").equalsIgnoreCase("true");
  }

  private String getTenantId(OpenstackVimInstance vimInstance, OSClient os)
      throws VimDriverException {
    return isV3API(vimInstance)
        ? vimInstance.getTenant()
        : getTenantIdFromName(os, vimInstance.getTenant());
  }

  private Optional<? extends org.openstack4j.model.network.Network> getNetworkByNameAndTenantId(
      OSClient os, String name, String tenantId) {
    return os.networking()
        .network()
        .list()
        .stream()
        .filter(n -> n.getName().equals(name) && (n.getTenantId().equals(tenantId) || n.isShared()))
        .findFirst();
  }

  private Optional<? extends AvailabilityZone> getZone(OSClient os, BaseVimInstance vimInstance) {
    String az = vimInstance.getMetadata().get("az");
    if (az == null) return Optional.empty();
    log.debug("Looking for availability zone with name: " + az);
    List<? extends AvailabilityZone> availabilityZones = os.compute().zones().list();
    return availabilityZones
        .stream()
        .filter(availabilityZone -> availabilityZone.getZoneName().equals(az))
        .findAny();
  }

  private Set<VNFDConnectionPoint> fixVNFDConnectionPoint(Set<VNFDConnectionPoint> networks) {
    Gson gson = new Gson();
    String oldVNFDCP = gson.toJson(networks);
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

  private String getImageIdFromName(BaseVimInstance vimInstance, String imageName)
      throws VimDriverException {
    log.debug("Retrieving id of the image named " + imageName + " on PoP " + vimInstance.getName());
    //    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    for (BaseNfvImage image4j : this.listImages(vimInstance)) {
      if (((NFVImage) image4j).getName().equals(imageName)
          || image4j.getExtId().equals(imageName)) {
        return image4j.getExtId();
      }
    }
    throw new VimDriverException("Not found image '" + imageName + "' on " + vimInstance.getName());
  }

  private String getExternalNetworkId(
      OSClient os, String tenantId, String internalNetworkName, BaseVimInstance vimInstance)
      throws Exception {
    String internalNetworkId = "";
    List<? extends org.openstack4j.model.network.Network> networks =
        os.networking().network().list();

    log.debug(
        "Looking for the external network id where the internal network "
            + internalNetworkName
            + " is connected to");

    for (org.openstack4j.model.network.Network network : networks) {
      if (network.getName().equals(internalNetworkName)
          && (network.getTenantId().equals(tenantId)
              || network.isShared()
              || network.isRouterExternal())) {
        internalNetworkId = network.getId();
        log.debug(String.format("Found network [%s] : %s", network.getId(), network.getName()));
        break;
      }
    }

    if (internalNetworkId.equals("")) {
      throw new Exception("The internal network name is invalid");
    }

    // because there are different ways to distinguish that a port is owned by a router get them all and then filter
    PortListOptions options = PortListOptions.create().networkId(internalNetworkId);
    List<? extends Port> ports = os.networking().port().list(options);
    log.trace("List of ports is " + new GsonBuilder().setPrettyPrinting().create().toJson(ports));
    Port routerPort = null;

    for (Port port : ports) {
      if (port.getDeviceOwner().contains("router")) {
        routerPort = port;
        break;
      }
    }

    if (null == routerPort) {
      log.debug(
          "Router port does not belong to project "
              + tenantId
              + ". Falling back to old mechanism for retrieving the external network ID.");
      return getExternalNet(vimInstance).getExtId();
      //      throw new Exception(
      //          "Cannot find a connection to a router, therefore cannot assign floating ip");
    }

    // major ASSUMPTION:  There will only be ONE router connected to a given internal network
    Router router = os.networking().router().get(routerPort.getDeviceId());
    log.debug(
        "The internal network "
            + internalNetworkId
            + " is connected to the router "
            + new GsonBuilder().setPrettyPrinting().create().toJson(router));
    return router.getExternalGatewayInfo().getNetworkId();
  }

  private List<NetFloatingIP> listFloatingIps(
      OSClient os, String tenantId, String internalNetworkName, OpenstackVimInstance vimInstance) {
    List<NetFloatingIP> res = new ArrayList<>();
    String externalNetworkId = "";
    if (!internalNetworkName.equals("")) {
      try {
        externalNetworkId = getExternalNetworkId(os, tenantId, internalNetworkName, vimInstance);
        log.debug("External network (name: " + internalNetworkName + ") id: " + externalNetworkId);
      } catch (Exception e) {
        log.error(e.getMessage(), e);
        return res;
      }
    }
    // assuming that the externalNetwork
    return listFloatingIps(os, tenantId, internalNetworkName, externalNetworkId);
  }

  private List<NetFloatingIP> listFloatingIps(
      OSClient os, String tenantId, String internalNetworkName, String externalNetworkId) {
    List<NetFloatingIP> res = new ArrayList<>();
    List<? extends NetFloatingIP> floatingIPs = os.networking().floatingip().list();
    log.trace(
        "Retrieved floating IP list: "
            + new GsonBuilder().setPrettyPrinting().create().toJson(floatingIPs));

    for (NetFloatingIP floatingIP : floatingIPs) {
      if (floatingIP.getTenantId().equals(tenantId)
          && (floatingIP.getFixedIpAddress() == null || floatingIP.getFixedIpAddress().equals(""))
          && (floatingIP.getFloatingNetworkId().equals(externalNetworkId)
              || internalNetworkName.equals(""))) {
        res.add(floatingIP);
      }
    }
    log.debug("floating ips being returned: " + res);
    return res;
  }

  private List<PopKeypair> listKeys(OpenstackVimInstance vimInstance) throws VimDriverException {
    OSClient cl = this.authenticate(vimInstance);
    List<PopKeypair> keys = new ArrayList<>();
    cl.compute()
        .keypairs()
        .list()
        .forEach(
            k -> {
              PopKeypair key = new PopKeypair();
              key.setName(k.getName());
              key.setPublicKey(k.getPublicKey());
              key.setFingerprint(k.getFingerprint());
              key.setProjectId(vimInstance.getProjectId());
              keys.add(key);
            });
    log.info(
        "Listed keys for PoP with name "
            + vimInstance.getName()
            + " and authURL "
            + vimInstance.getAuthUrl());
    log.debug(new GsonBuilder().setPrettyPrinting().create().toJson(keys));
    return keys;
  }

  @Override
  public List<BaseNfvImage> listImages(BaseVimInstance vimInstance) throws VimDriverException {
    try {
      OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
      Map<String, String> map = new HashMap<>();
      map.put("limit", "100");
      List<? extends org.openstack4j.model.image.v2.Image> v2Images = new ArrayList<>();
      List<? extends Image> v1Images = new ArrayList<>();
      List<BaseNfvImage> nfvImages = new ArrayList<>();

      Exception exceptionListingV2 = null;
      try {
        log.debug(
            "Listing images for VIM "
                + vimInstance.getName()
                + " ("
                + vimInstance.getId()
                + ") using Glance v2.");
        v2Images = os.imagesV2().list(map);
        log.trace(
            "Listed images for VIM "
                + vimInstance.getName()
                + " ("
                + vimInstance.getId()
                + "): "
                + v2Images);
      } catch (Exception e) {
        log.warn(
            "Listing images of VIM "
                + vimInstance.getName()
                + " ("
                + vimInstance.getId()
                + ") using Glance v2 threw exception: "
                + e.getMessage());
        exceptionListingV2 = e;
      }
      if (v2Images.isEmpty()) {
        log.debug("No images found using Glance v2. Falling back to v1.");
        try {
          v1Images = os.images().list(map);
          log.trace(
              "Listed images for VIM "
                  + vimInstance.getName()
                  + " ("
                  + vimInstance.getId()
                  + "): "
                  + v2Images);
        } catch (Exception e) {
          log.warn(
              "Listing images of VIM "
                  + vimInstance.getName()
                  + " ("
                  + vimInstance.getId()
                  + ") using Glance v1 threw exception: "
                  + e.getMessage());
          if (exceptionListingV2 != null)
            throw new VimDriverException(
                "Listing images of VIM "
                    + vimInstance.getName()
                    + " ("
                    + vimInstance.getId()
                    + ") threw exceptions using Glance v2: \""
                    + exceptionListingV2.getMessage()
                    + "\" and using Glance v1: \""
                    + e.getMessage()
                    + "\"");
        }
        for (Image image : v1Images) nfvImages.add(Utils.getImage(image));
      } else {
        for (org.openstack4j.model.image.v2.Image image : v2Images)
          nfvImages.add(Utils.getImageV2(image));
      }

      log.info(
          "Listed "
              + nfvImages.size()
              + " images for BaseVimInstance "
              + vimInstance.getName()
              + " ("
              + vimInstance.getId()
              + ") : "
              + String.join(
                  ", ",
                  nfvImages
                      .stream()
                      .map(i -> ((NFVImage) i).getName() + " (" + i.getExtId() + ")")
                      .collect(Collectors.toList())));

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
                && srv.getTenantId()
                    .equals(getTenantIdFromName(os, openstackVimInstance.getTenant()))))) {
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
      log.info(
          "Listed networks for PoP with name "
              + vimInstance.getName()
              + " and authURL "
              + vimInstance.getAuthUrl());
      log.debug(new GsonBuilder().setPrettyPrinting().create().toJson(networks));
      List<BaseNetwork> nfvNetworks = new ArrayList<>();
      for (org.openstack4j.model.network.Network network : networks) {
        if ((network.isRouterExternal() || network.isShared())
            || (isV3API(vimInstance)
                    && network.getTenantId().equals(openstackVimInstance.getTenant())
                || (!isV3API(vimInstance)
                    && network
                        .getTenantId()
                        .equals(getTenantIdFromName(os, openstackVimInstance.getTenant()))))) {
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

  private String getTenantIdFromName(OSClient os, String tenantName) throws VimDriverException {
    log.trace("Getting id of tenant with name " + tenantName);
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
      throws VimDriverException {
    log.trace(
        "Getting Subnet with extId: " + subnetId + " from PoP with name: " + vimInstance.getName());
    try {
      org.openstack4j.model.network.Subnet subnet = os.networking().subnet().get(subnetId);
      log.trace("Found subnet: " + new GsonBuilder().setPrettyPrinting().create().toJson(subnet));
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

  public Server rebuildServer(BaseVimInstance vimInstance, String serverId, String imageId)
      throws VimDriverException {
    OpenstackVimInstance openstackVimInstance = (OpenstackVimInstance) vimInstance;
    OSClient os = this.authenticate(openstackVimInstance);
    RebuildOptions rebuildOptions = RebuildOptions.create();
    if (imageId != null) {
      rebuildOptions.image(imageId);
      log.info("Rebuilding server: " + serverId + " with image: " + imageId);
    } else log.info("Rebuilding server: " + serverId);
    ActionResponse response = os.compute().servers().rebuild(serverId, rebuildOptions);
    if (!response.isSuccess()) {
      log.error("Error rebuilding image: " + response.getFault());
      throw new VimDriverException("Error rebuilding image: " + response.getFault());
    }
    return Utils.getServer(os.compute().servers().get(serverId));
  }

  @Override
  public List<DeploymentFlavour> listFlavors(BaseVimInstance vimInstance)
      throws VimDriverException {
    List<DeploymentFlavour> deploymentFlavours = new ArrayList<>();
    try {
      OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
      List<? extends Flavor> flavors = os.compute().flavors().list();
      log.info(
          "Listed flavors for PoP with name "
              + vimInstance.getName()
              + " and authURL "
              + vimInstance.getAuthUrl());
      log.debug(new GsonBuilder().setPrettyPrinting().create().toJson(flavors));
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
    log.info(String.format("Refreshing vim instance: %s", openstackVimInstance.getName()));
    ExecutorService executor = Executors.newFixedThreadPool(5);

    final Exception[] e = new Exception[5];
    executor.execute(
        () -> {
          List<BaseNfvImage> newImages;
          try {
            newImages = listImages(vimInstance);
          } catch (VimDriverException e1) {
            e[0] = e1;
            return;
          }
          if (openstackVimInstance.getImages() == null) {
            openstackVimInstance.setImages(new HashSet<>());
          }
          openstackVimInstance.getImages().clear();
          openstackVimInstance.addAllImages(newImages);
        });
    executor.execute(
        () -> {
          List<BaseNetwork> newNetworks;
          try {
            newNetworks = listNetworks(vimInstance);
          } catch (VimDriverException e1) {
            e[1] = e1;
            return;
          }

          if (openstackVimInstance.getNetworks() == null) {
            openstackVimInstance.setNetworks(new HashSet<>());
          }
          openstackVimInstance.getNetworks().clear();
          openstackVimInstance.addAllNetworks(newNetworks);
        });
    executor.execute(
        () -> {
          List<DeploymentFlavour> newFlavors;
          try {
            newFlavors = listFlavors(vimInstance);
          } catch (VimDriverException e1) {
            e[2] = e1;
            return;
          }
          if (openstackVimInstance.getFlavours() == null) {
            openstackVimInstance.setFlavours(new HashSet<>());
          }
          openstackVimInstance.getFlavours().clear();
          openstackVimInstance.getFlavours().addAll(newFlavors);
        });
    executor.execute(
        () -> {
          List<org.openbaton.catalogue.nfvo.viminstances.AvailabilityZone> newAvalabilityZones;
          try {
            newAvalabilityZones = listAvailabilityZone(vimInstance);
          } catch (VimDriverException e1) {
            e[3] = e1;
            return;
          }
          if (openstackVimInstance.getZones() == null) {
            openstackVimInstance.setZones(new HashSet<>());
          }
          openstackVimInstance.getZones().clear();
          openstackVimInstance.getZones().addAll(newAvalabilityZones);
        });
    executor.execute(
        () -> {
          List<PopKeypair> keys;
          try {
            keys = listKeys(openstackVimInstance);
          } catch (VimDriverException e1) {
            e[4] = e1;
            return;
          }
          if (openstackVimInstance.getKeys() == null) {
            openstackVimInstance.setKeys(new HashSet<>());
          }
          openstackVimInstance.getKeys().clear();
          openstackVimInstance.getKeys().addAll(keys);
        });
    executor.shutdown();
    try {
      if (!executor.awaitTermination(300, TimeUnit.SECONDS)) {
        throw new VimDriverException(
            "Timeout waiting for the refresh, probably openstack will never answer...");
      }
    } catch (InterruptedException e1) {
      e1.printStackTrace();
    }
    Optional<Exception> exception = Arrays.stream(e).filter(Objects::nonNull).findAny();
    if (exception.isPresent()) {
      throw new VimDriverException("Error refreshing vim", exception.get());
    }
    return openstackVimInstance;
  }

  private List<org.openbaton.catalogue.nfvo.viminstances.AvailabilityZone> listAvailabilityZone(
      BaseVimInstance vimInstance) throws VimDriverException {
    List<org.openbaton.catalogue.nfvo.viminstances.AvailabilityZone> res = new ArrayList<>();
    for (AvailabilityZone az :
        authenticate((OpenstackVimInstance) vimInstance).compute().zones().list()) {
      res.add(Utils.getAvailabilityZone(az));
    }
    return res;
  }

  @Override
  public Server launchInstanceAndWait(
      BaseVimInstance vimInstance,
      String instanceName,
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
    OpenstackVimInstance openstackVimInstance = (OpenstackVimInstance) vimInstance;
    OSClient os = this.authenticate(openstackVimInstance);

    Server server =
        this.launchInstance(
            os,
            openstackVimInstance,
            instanceName,
            image,
            flavor,
            keyPair,
            networks,
            securityGroups,
            userdata);
    org.openstack4j.model.compute.Server server4j = null;
    try {
      log.info(
          "Deployed VM ( "
              + server.getName()
              + " ) with extId: "
              + server.getExtId()
              + " in status "
              + server.getStatus());
      while (!bootCompleted) {
        log.debug(
            "Waiting for VM with hostname "
                + instanceName
                + " to become ACTIVE. Currently in status ("
                + server.getStatus()
                + ")");
        try {
          Thread.sleep(Integer.parseInt(waitForVM));
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
        server4j = getServerById(os, server.getExtId());
        server = Utils.getServer(server4j);
        if (server.getStatus().equalsIgnoreCase("ACTIVE")) {
          log.info("Finished deployment of VM with hostname: " + instanceName);
          bootCompleted = true;
        }
        if (server.getExtendedStatus().equalsIgnoreCase("ERROR")
            || server.getStatus().equalsIgnoreCase("ERROR")) {
          log.error(
              "Failed to launch VM with hostname: " + instanceName + " -> " + server4j.getFault());
          VimDriverException vimDriverException =
              new VimDriverException(server.getExtendedStatus());
          vimDriverException.setServer(server);
          throw vimDriverException;
        }
      }
      associateFloatingIps(os, openstackVimInstance, instanceName, networks, server, server4j);
    } catch (Exception e) {
      log.error(e.getMessage());
      VimDriverException exception;
      if (!(e instanceof VimDriverException)) exception = new VimDriverException(e.getMessage(), e);
      else exception = (VimDriverException) e;
      if (server != null) {
        exception.setServer(server);
      } else if (server4j != null) {
        exception.setServer(Utils.getServer(server4j));
      }
      throw exception;
    }
    log.info("Virtual Server " + server.getName() + " successfully launched");
    log.trace(new GsonBuilder().setPrettyPrinting().create().toJson(server));
    return server;
  }

  private void associateFloatingIps(
      OSClient os,
      OpenstackVimInstance openstackVimInstance,
      String instanceName,
      Set<VNFDConnectionPoint> networks,
      Server server,
      org.openstack4j.model.compute.Server server4j)
      throws Exception {
    if (server.getFloatingIps() == null) {
      server.setFloatingIps(new HashMap<>());
    }
    log.info("Checking if VM with hostname " + instanceName + " requires Floating IPs");
    String tenantId = getTenantId(openstackVimInstance, os);

    for (VNFDConnectionPoint vnfdConnectionPoint : networks) {
      log.debug(
          "Connection point is: "
              + new GsonBuilder().setPrettyPrinting().create().toJson(vnfdConnectionPoint));
      if (null != vnfdConnectionPoint.getFloatingIp()) {
        try {
          OpenStack4JDriver.lock.lock();
          server
              .getFloatingIps()
              .put(
                  vnfdConnectionPoint.getVirtual_link_reference(),
                  this.translateToNAT(
                      associateFloatingIpToNetwork(
                          os, tenantId, server4j, vnfdConnectionPoint, openstackVimInstance)));
        } finally {
          OpenStack4JDriver.lock.unlock();
        }
      }
    }
    log.info(
        "Assigned FloatingIPs to VM with hostname: "
            + instanceName
            + " -> FloatingIPs: "
            + server.getFloatingIps());
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
      log.trace("Source CIDR is: " + fromCidr);
      SubnetUtils utilsFrom = new SubnetUtils(fromCidr);
      SubnetUtils utilsTo = new SubnetUtils(toCidr);

      SubnetUtils.SubnetInfo subnetInfoFrom = utilsFrom.getInfo();
      SubnetUtils.SubnetInfo subnetInfoTo = utilsTo.getInfo();
      InetAddress floatingIpNetAddr = InetAddress.getByName(floatingIp);
      if (subnetInfoFrom.isInRange(floatingIp)) { //translation!

        log.debug(
            "From networkMask "
                + subnetInfoFrom.getNetmask()
                + " to networkMask "
                + subnetInfoTo.getNetmask());
        if (!subnetInfoFrom.getNetmask().equals(subnetInfoTo.getNetmask())) {
          log.error("Translation is not possible since netmasks are different");
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
          int intValue = Byte.valueOf((byte) (netaddress[i] | host[i])).intValue();
          if (intValue < 0) intValue = intValue & 0xFF;
          result[i] = String.valueOf(intValue);
        }

        return String.join(".", result);
      }
    }
    return floatingIp;
  }

  private org.openstack4j.model.compute.Server getServerById(OSClient os, String extId) {
    return os.compute().servers().get(extId);
  }

  private String associateFloatingIpToNetwork(
      OSClient os,
      String tenantId,
      org.openstack4j.model.compute.Server server4j,
      VNFDConnectionPoint vnfdConnectionPoint,
      OpenstackVimInstance openstackVimInstance)
      throws Exception {
    String poolName = "";
    String extNetworkId = "";

    // allocate another floating ip if needed
    try {
      if (vnfdConnectionPoint.getChosenPool() != null
          && !vnfdConnectionPoint.getChosenPool().equals("")) {
        poolName = vnfdConnectionPoint.getChosenPool();
        String finalPoolName = poolName;
        extNetworkId =
            (openstackVimInstance
                .getNetworks()
                .stream()
                .filter(n -> n.getName().equals(finalPoolName))
                .findFirst()
                .orElseThrow(() -> new VimDriverException("Network not found"))
                .getExtId());
      } else {
        extNetworkId =
            getExternalNetworkId(
                os,
                tenantId,
                vnfdConnectionPoint.getVirtual_link_reference(),
                openstackVimInstance);
        log.debug(
            "Retrieved external network: "
                + new GsonBuilder()
                    .setPrettyPrinting()
                    .create()
                    .toJson(os.networking().network().get(extNetworkId)));
        poolName = os.networking().network().get(extNetworkId).getName();
        log.info("pool name is " + poolName);
      }
    } catch (Exception e) {
      log.error(e.getMessage());
    }
    log.info("vnfdConnectionPoint: " + vnfdConnectionPoint);
    if ((vnfdConnectionPoint.getFloatingIp().trim().equalsIgnoreCase("random")
            || vnfdConnectionPoint.getFloatingIp().trim().equals(""))
        && (listFloatingIps(
                    os, tenantId, vnfdConnectionPoint.getVirtual_link_reference(), extNetworkId)
                .size()
            <= 0)) {
      log.info(
          "Allocating a new floating ip to project ("
              + tenantId
              + ") from pool "
              + poolName
              + " with external network ID: "
              + extNetworkId);
      os.compute().floatingIps().allocateIP(poolName);
    }

    PortListOptions options = PortListOptions.create().name(buildPortName(vnfdConnectionPoint));
    List<? extends Port> ports = os.networking().port().list(options);
    log.debug("List of ports is " + new GsonBuilder().setPrettyPrinting().create().toJson(ports));

    if (null == ports || ports.isEmpty()) {
      throw new VimDriverException(
          "cannot find the port associated with vnfdConnectionPoint " + vnfdConnectionPoint);
    } else if (null == ports.get(0).getFixedIps() || ports.get(0).getFixedIps().isEmpty()) {
      throw new VimDriverException(
          "cannot find the fixed ips associated with port " + ports.get(0));
    }

    boolean success = true;
    String floatingIpAddress = "";
    // assuming that the poolName is equal to the network name. TODO find a better approach
    floatingIpAddress =
        findFloatingIpAddress(
                os,
                vnfdConnectionPoint.getFloatingIp(),
                tenantId,
                vnfdConnectionPoint.getVirtual_link_reference(),
                openstackVimInstance)
            .getFloatingIpAddress();
    log.debug("floatingIpAddress: " + floatingIpAddress);
    success =
        success
            && os.compute()
                .floatingIps()
                .addFloatingIP(
                    server4j,
                    ports.get(0).getFixedIps().iterator().next().getIpAddress(),
                    floatingIpAddress)
                .isSuccess();
    log.debug("success = " + success);

    if (success) {
      log.debug("Associated fip " + floatingIpAddress + " with server " + server4j);
      return floatingIpAddress;
    }
    throw new VimDriverException(
        "Not able to associate fip "
            + vnfdConnectionPoint.getFloatingIp()
            + " to instance "
            + server4j.getName());
  }

  private NetFloatingIP findFloatingIpAddress(
      OSClient os,
      String fipValue,
      String tenantId,
      String internalNetworkName,
      OpenstackVimInstance vimInstance)
      throws Exception {
    if (fipValue.trim().equalsIgnoreCase("random") || fipValue.trim().equals("")) {
      return listFloatingIps(os, tenantId, internalNetworkName, vimInstance).get(0);
    }

    List<? extends NetFloatingIP> netFloatingIPS = os.networking().floatingip().list();
    for (NetFloatingIP fip : netFloatingIPS) {
      if (fip.getFloatingIpAddress().equals(fipValue)
          && (null == fip.getFixedIpAddress() || fip.getFixedIpAddress().equals(""))
          && fip.getTenantId().equals(tenantId)) {
        return fip;
      }
    }

    this.log.info(String.format("Floating ip %s not allocated, try to allocate", fipValue));

    NeutronFloatingIP floatingIp = new NeutronFloatingIP();
    floatingIp.setTenantId(tenantId);
    floatingIp.setFloatingIpAddress(fipValue);
    floatingIp.setFloatingNetworkId(
        getExternalNetworkId(os, tenantId, internalNetworkName, vimInstance));
    return os.networking().floatingip().create(floatingIp);

    //    throw new VimDriverException("Floating ip " + fipValue + " not found");

    //    return os.networking()
    //        .floatingip()
    //        .list()
    //        .stream()
    //        .filter(
    //            floatingIP -> {
    //              this.log.debug(String.format("Checking fip %s, fixed ip: %s", floatingIP.getFloatingIpAddress(), floatingIP.getFixedIpAddress()));
    //              return floatingIP.getFloatingIpAddress().equalsIgnoreCase(fipValue);
    //            })
    //        .findFirst()
    //        .orElseThrow(() -> new VimDriverException("Floating ip " + fipValue + " not found"));
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
    OpenstackVimInstance openstackVimInstance = (OpenstackVimInstance) vimInstance;
    OSClient os = this.authenticate(openstackVimInstance);
    /* I suppose that checking for the result waits also for the effectivness of the operation */
    if (Boolean.parseBoolean(properties.getProperty("deallocate-floating-ip", "true"))) {
      log.info("Deallocating floating IP for VM with external id " + id);
      org.openstack4j.model.compute.Server server = os.compute().servers().get(id);
      server
          .getAddresses()
          .getAddresses()
          .forEach(
              (k, v) ->
                  v.forEach(
                      ip -> {
                        log.trace(
                            String.format("IP %s is of type: %s", ip.getAddr(), ip.getType()));
                        if (ip.getType().contains("floating")) {
                          os.compute().floatingIps().removeFloatingIP(id, ip.getAddr());
                          try {
                            os.networking()
                                .floatingip()
                                .delete(
                                    this.findFloatingIpAddress(
                                            os,
                                            ip.getAddr(),
                                            getTenantId(openstackVimInstance, os),
                                            "",
                                            openstackVimInstance)
                                        .getId());
                          } catch (Exception e) {
                            e.printStackTrace();
                          }
                        }
                      }));
    }
    // Delete all the ports associated with the server
    PortListOptions options = PortListOptions.create().deviceId(id);
    List<? extends Port> ports = os.networking().port().list(options);
    log.debug("List of ports is " + new GsonBuilder().setPrettyPrinting().create().toJson(ports));
    for (Port port : ports) {
      os.networking().port().delete(port.getId());
    }

    log.info(
        "Deleting VM with id "
            + id
            + ", result is: "
            + (os.compute().servers().delete(id).isSuccess() ? "Success" : "Failure!"));
  }

  @Override
  public BaseNetwork createNetwork(BaseVimInstance vimInstance, BaseNetwork network)
      throws VimDriverException {

    Network osNetwork = (Network) network;
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    org.openstack4j.model.network.Network network4j =
        os.networking()
            .network()
            .create(
                Builders.network()
                    .name(osNetwork.getName())
                    .adminStateUp(true)
                    .isShared(osNetwork.getExtShared())
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
              && router
                  .getTenantId()
                  .equals(getTenantIdFromName(os, openstackVimInstance.getTenant()))))) {
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
      if (null == router) {
        throw new VimDriverException("Unable to create router");
      }
      iface =
          os.networking()
              .router()
              .attachInterface(router.getId(), AttachInterfaceType.SUBNET, subnetExtId);
      if (null == iface) {
        // failed to attach router, delete the router
        os.networking().router().delete(router.getId());
      }
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

      if (((Network) net).getExternal()) {
        return ((Network) net);
      }
    }
    throw new VimDriverException("No External Network found! please add one");
  }

  @Override
  public DeploymentFlavour addFlavor(
      BaseVimInstance vimInstance, DeploymentFlavour deploymentFlavour) throws VimDriverException {
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    //TODO add missing parameter to deployment flavor, hopefully fixed with etsi v2.1.1
    Flavor flavor =
        os.compute()
            .flavors()
            .create(
                Builders.flavor()
                    .name(deploymentFlavour.getFlavour_key())
                    .disk(deploymentFlavour.getDisk())
                    .isPublic(true)
                    .ram(deploymentFlavour.getRam())
                    .vcpus(deploymentFlavour.getVcpus())
                    .build());

    return Utils.getFlavor(flavor);
  }

  @Override
  public BaseNfvImage addImage(
      final BaseVimInstance vimInstance, BaseNfvImage image, String image_url)
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
  public BaseNfvImage updateImage(BaseVimInstance vimInstance, BaseNfvImage image) {
    return null;
  }

  @Override
  public BaseNfvImage copyImage(BaseVimInstance vimInstance, BaseNfvImage image, byte[] imageFile) {
    return null;
  }

  @Override
  public boolean deleteImage(BaseVimInstance vimInstance, BaseNfvImage image)
      throws VimDriverException {
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    return os.images().delete(image.getExtId()).isSuccess();
  }

  @Override
  public DeploymentFlavour updateFlavor(
      BaseVimInstance vimInstance, DeploymentFlavour deploymentFlavour) {
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
    SubnetBuilder subnetBuilder =
        Builders.subnet()
            .name(subnet.getName())
            .networkId(createdNetwork.getExtId())
            .ipVersion(IPVersionType.V4)
            .cidr(subnet.getCidr())
            .enableDHCP(true)
            .gateway(subnet.getGatewayIp());

    if (subnet.getDns() != null && !subnet.getDns().isEmpty())
      subnet
          .getDns()
          .forEach(
              dns -> {
                log.info(String.format("Adding DNS: %s", dns));
                subnetBuilder.addDNSNameServer(dns);
              });
    else {
      String dns = properties.getProperty("openstack4j.dns.ip", "8.8.8.8");
      log.info(String.format("Adding DNS: %s", dns));
      subnetBuilder.addDNSNameServer(dns);
    }
    org.openstack4j.model.network.Subnet subnet4j =
        os.networking().subnet().create(subnetBuilder.build());

    Subnet sn = Utils.getSubnet(subnet4j);
    try {
      attachToRouter(os, sn.getExtId(), vimInstance);
    } catch (VimDriverException e) {
      log.error(e.getMessage());

      // if we could not attach the router to the delete the subnet
      try {
        deleteSubnet(vimInstance, sn.getExtId());
      } catch (VimDriverException e2) {
        log.error(e.getMessage());
      }
      throw new VimDriverException("Deleted subnet");
    }
    return sn;
  }

  //TODO need to chage byte[] to stream, at least...
  @Override
  public BaseNfvImage addImage(BaseVimInstance vimInstance, BaseNfvImage image, byte[] imageFile) {
    throw new UnsupportedOperationException();
  }

  @Override
  public BaseNetwork updateNetwork(BaseVimInstance vimInstance, BaseNetwork network) {
    return null;
  }

  @Override
  public Subnet updateSubnet(
      BaseVimInstance vimInstance, BaseNetwork updatedNetwork, Subnet subnet) {
    return null;
  }

  @Override
  public List<String> getSubnetsExtIds(BaseVimInstance vimInstance, String network_extId) {
    return null;
  }

  @Override
  public boolean deleteSubnet(BaseVimInstance vimInstance, String existingSubnetExtId)
      throws VimDriverException {
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);
    return os.networking().subnet().delete(existingSubnetExtId).isSuccess();
  }

  @Override
  public boolean deleteNetwork(BaseVimInstance vimInstance, String extId)
      throws VimDriverException {
    OSClient os = this.authenticate((OpenstackVimInstance) vimInstance);

    new Thread(
            () -> {
              OSClient osClient;
              try {
                osClient = this.authenticate((OpenstackVimInstance) vimInstance);
              } catch (VimDriverException e) {
                e.printStackTrace();
                return;
              }
              int attempts = 0;
              boolean success = false;
              log.debug(String.format("Trying deleting Network %s", extId));
              while (attempts < 10 && !success) {
                org.openstack4j.model.network.Network network =
                    os.networking().network().get(extId);
                try {
                  Thread.sleep(1000);
                } catch (InterruptedException e) {
                  e.printStackTrace();
                }
                if (!network.getSubnets().isEmpty()) {
                  try {
                    network
                        .getSubnets()
                        .forEach(
                            subnetId -> {
                              for (Router r : os.networking().router().list()) {
                                os.networking()
                                    .port()
                                    .list()
                                    .stream()
                                    .filter(
                                        p ->
                                            p.getDeviceOwner().equals("network:router_interface")
                                                && p.getDeviceId().equals(r.getId())
                                                && p.getFixedIps()
                                                    .stream()
                                                    .anyMatch(
                                                        ip -> ip.getSubnetId().equals(subnetId)))
                                    .forEach(
                                        p -> {
                                          log.debug(
                                              String.format(
                                                  "Detaching subnet %s from router %s identified by port %s",
                                                  subnetId, r.getId(), p.getId()));
                                          os.networking()
                                              .router()
                                              .detachInterface(r.getId(), subnetId, p.getId());
                                        });
                              }
                            });
                  } catch (Throwable e) {
                    attempts++;
                    success = false;
                    continue;
                  }
                }

                success = osClient.networking().network().delete(extId).isSuccess();
                attempts++;
              }
              if (!success) {
                log.error(String.format("Not able to delete network with id %s", extId));
              } else {
                log.info(String.format("Deleted network %s", extId));
              }
            })
        .start();
    return true;
  }

  @Override
  public BaseNetwork getNetworkById(BaseVimInstance vimInstance, String id)
      throws VimDriverException {
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
  public String getType(BaseVimInstance vimInstance) {
    return "openstack";
  }
}
