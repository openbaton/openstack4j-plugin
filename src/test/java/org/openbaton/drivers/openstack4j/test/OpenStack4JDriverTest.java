/*
 * Copyright (c) 2015-2018 Open Baton (http://openbaton.org)
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

package org.openbaton.drivers.openstack4j.test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.openbaton.catalogue.mano.common.DeploymentFlavour;
import org.openbaton.catalogue.mano.descriptor.VNFDConnectionPoint;
import org.openbaton.catalogue.nfvo.Server;
import org.openbaton.catalogue.nfvo.images.BaseNfvImage;
import org.openbaton.catalogue.nfvo.networks.BaseNetwork;
import org.openbaton.catalogue.nfvo.viminstances.OpenstackVimInstance;
import org.openbaton.drivers.openstack4j.OpenStack4JDriver;
import org.openbaton.exceptions.VimDriverException;
import org.openstack4j.api.OSClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Created by lto on 11/01/2017. */
public class OpenStack4JDriverTest {
  private static Properties properties;
  private static Logger log = LoggerFactory.getLogger(OpenStack4JDriverTest.class);
  private static OpenStack4JDriver osd;
  private static OpenstackVimInstance vimInstance;

  @BeforeClass
  public static void init() throws IOException {
    properties = new Properties();
    try {
      InputStream resourceAsStream = null;
      try {
        resourceAsStream = OpenStack4JDriverTest.class.getResourceAsStream("/test.properties");
      } catch (NullPointerException e) {
        log.warn("test.properties not found, using default values");
      }
      if (resourceAsStream != null) properties.load(new InputStreamReader(resourceAsStream));
    } catch (IOException e) {
      log.error("Missing 'test.properties' file, please use test.properties.default to create it");
    }
    osd = new OpenStack4JDriver();
    vimInstance = getVimInstance();
  }

  @Test
  @Ignore
  public void authenticate() throws VimDriverException {
    OSClient os = osd.authenticate(vimInstance);
    log.debug("Endpoint is: " + os.getEndpoint());
    assert os.getEndpoint() != null;
  }

  @Test
  public void launchInstance() throws VimDriverException {}

  @Test
  @Ignore
  public void listImages() throws VimDriverException {
    try {
      for (BaseNfvImage image : osd.listImages(vimInstance)) {
        log.info(image.toString());
      }
    } catch (VimDriverException e) {
      e.printStackTrace();
      throw e;
    }
  }

  @Test
  @Ignore
  public void listServer() throws VimDriverException {
    for (Server server : osd.listServer(vimInstance)) {
      log.info(server.toString());
    }
  }

  @Test
  @Ignore
  public void listNetworks() throws VimDriverException {
    try {
      for (BaseNetwork network : osd.listNetworks(vimInstance)) {
        log.info("Network: " + network.toString());
      }
    } catch (VimDriverException e) {
      e.printStackTrace();
      throw e;
    }
  }

  @Test
  @Ignore
  public void listFlavors() throws VimDriverException {
    try {
      for (DeploymentFlavour flavour : osd.listFlavors(vimInstance)) {
        log.info(flavour.toString());
      }
    } catch (VimDriverException e) {
      e.printStackTrace();
      throw e;
    }
  }

  @Test
  @Ignore
  public void launchInstanceAndWait() throws VimDriverException, IOException {

    Map<String, String> fips = new HashMap<>();
    List<String> networksNames =
        Arrays.asList(
            properties.getProperty("vim.instance.network.names", "mgmt;private").split(";"));
    for (String netName : networksNames) {
      fips.put(netName, "random");
      break;
    }
    Set<VNFDConnectionPoint> connectionPoints = new HashSet<>();
    int interFaceId = 0;
    for (String name : networksNames) {
      VNFDConnectionPoint cp = new VNFDConnectionPoint();
      cp.setVirtual_link_reference(name);
      cp.setInterfaceId(interFaceId++);
      connectionPoints.add(cp);
    }

    String userdata = "";

    File userdataFilePath =
        new File(
            properties.getProperty(
                "vim.instance.userdata.path", "/etc/openbaton/openstack4j-test/userdata.sh"));
    if (userdataFilePath.exists()) {
      userdata = new String(Files.readAllBytes(Paths.get(userdataFilePath.getAbsolutePath())));
    }

    Server server =
        osd.launchInstanceAndWait(
            vimInstance,
            "test",
            properties.getProperty("vim.instance.image.name", "Ubuntu 14.04.4 x86_64"),
            properties.getProperty("vim.instance.flavor.name", "m1.small"),
            properties.getProperty("vim.instance.keypair.name", "stack"),
            connectionPoints,
            new HashSet<String>(
                Arrays.asList(
                    properties
                        .getProperty("vim.instance.securitygroups.names", "default")
                        .split(";"))),
            userdata,
            fips,
            null);

    log.info("Created Server: " + server);

    osd.deleteServerByIdAndWait(vimInstance, server.getExtId());
  }

  @Test
  public void deleteServerByIdAndWait() throws VimDriverException {}

  @Test
  public void createNetwork() throws VimDriverException {}

  @Test
  public void addFlavor() throws VimDriverException {}

  @Test
  public void addImage() throws VimDriverException {}

  @Test
  public void addImage1() throws VimDriverException {}

  @Test
  public void updateImage() throws VimDriverException {}

  @Test
  public void copyImage() throws VimDriverException {}

  @Test
  public void deleteImage() throws VimDriverException {}

  @Test
  public void updateFlavor() throws VimDriverException {}

  @Test
  public void deleteFlavor() throws VimDriverException {}

  @Test
  public void createSubnet() throws VimDriverException {}

  @Test
  public void updateNetwork() throws VimDriverException {}

  @Test
  public void updateSubnet() throws VimDriverException {}

  @Test
  public void getSubnetsExtIds() throws VimDriverException {}

  @Test
  public void deleteSubnet() throws VimDriverException {}

  @Test
  public void deleteNetwork() throws VimDriverException {}

  @Test
  public void getNetworkById() throws VimDriverException {}

  @Test
  @Ignore
  public void getQuota() throws VimDriverException {
    log.info(osd.getQuota(vimInstance).toString());
  }

  public static void main(String[] args) throws VimDriverException, IOException {
    init();
    OpenStack4JDriver osd = new OpenStack4JDriver();
    OpenstackVimInstance vimInstance = getVimInstance();
    OSClient cl = osd.authenticate(vimInstance);
    //    cl.compute().zones().list().forEach(z -> z.getHosts().forEach((key, value) -> System.out.println(key + " -> " + value.get("").)));
  }

  private static OpenstackVimInstance getVimInstance() {
    OpenstackVimInstance vimInstance = new OpenstackVimInstance();
    vimInstance.setName(properties.getProperty("vim.instance.name", "test"));
    vimInstance.setAuthUrl(
        properties.getProperty("vim.instance.url", "http://127.0.0.1/identity/v3"));
    vimInstance.setUsername(properties.getProperty("vim.instance.username", "test"));
    vimInstance.setPassword(properties.getProperty("vim.instance.password", "test"));
    if (properties.getProperty("vim.instance.project.id") != null) {
      vimInstance.setTenant(properties.getProperty("vim.instance.project.id"));
    } else {
      vimInstance.setTenant(properties.getProperty("vim.instance.project.name", "test"));
    }
    return vimInstance;
  }
}
