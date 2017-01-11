package org.openbaton.drivers.openstack4j.test;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Properties;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openbaton.catalogue.nfvo.NFVImage;
import org.openbaton.catalogue.nfvo.Network;
import org.openbaton.catalogue.nfvo.VimInstance;
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
  private static VimInstance vimInstance;

  @BeforeClass
  public static void init() throws IOException {
    properties = new Properties();
    try {
      properties.load(
          new InputStreamReader(
              OpenStack4JDriverTest.class.getResourceAsStream("/test.properties")));
    } catch (IOException e) {
      log.error("Missing test.properties file");
      throw e;
    }
    osd = new OpenStack4JDriver();
    vimInstance = getVimInstance();
  }

  @Test
  public void authenticate() throws Exception {
    OSClient.OSClientV3 os = osd.authenticate(vimInstance);
    log.debug("Token is: " + os.getToken());
    assert os.getToken() != null;
  }

  @Test
  public void launchInstance() throws Exception {}

  @Test
  public void listImages() throws Exception {
    try {
      for (NFVImage image : osd.listImages(vimInstance)) {
        log.info(image.toString());
      }
    } catch (VimDriverException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void listServer() throws Exception {}

  @Test
  public void listNetworks() throws Exception {
    try {
      for (Network network : osd.listNetworks(vimInstance)) {
        log.info(network.toString());
      }
    } catch (VimDriverException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void listFlavors() throws Exception {}

  @Test
  public void launchInstanceAndWait() throws Exception {}

  @Test
  public void launchInstanceAndWait1() throws Exception {}

  @Test
  public void deleteServerByIdAndWait() throws Exception {}

  @Test
  public void createNetwork() throws Exception {}

  @Test
  public void addFlavor() throws Exception {}

  @Test
  public void addImage() throws Exception {}

  @Test
  public void addImage1() throws Exception {}

  @Test
  public void updateImage() throws Exception {}

  @Test
  public void copyImage() throws Exception {}

  @Test
  public void deleteImage() throws Exception {}

  @Test
  public void updateFlavor() throws Exception {}

  @Test
  public void deleteFlavor() throws Exception {}

  @Test
  public void createSubnet() throws Exception {}

  @Test
  public void updateNetwork() throws Exception {}

  @Test
  public void updateSubnet() throws Exception {}

  @Test
  public void getSubnetsExtIds() throws Exception {}

  @Test
  public void deleteSubnet() throws Exception {}

  @Test
  public void deleteNetwork() throws Exception {}

  @Test
  public void getNetworkById() throws Exception {}

  @Test
  public void getQuota() throws Exception {}

  public static void main(String[] args) throws VimDriverException {

    OpenStack4JDriver osd = new OpenStack4JDriver();
    VimInstance vimInstance = getVimInstance();
    osd.authenticate(vimInstance);
  }

  private static VimInstance getVimInstance() {
    VimInstance vimInstance = new VimInstance();
    vimInstance.setName(properties.getProperty("vim.instance.name"));
    vimInstance.setAuthUrl(properties.getProperty("vim.instance.url"));
    vimInstance.setUsername(properties.getProperty("vim.instance.username"));
    vimInstance.setPassword(properties.getProperty("vim.instance.password"));
    vimInstance.setTenant(properties.getProperty("vim.instance.project.id"));
    return vimInstance;
  }
}
