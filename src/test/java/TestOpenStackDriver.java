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

/** Created by gca on 10/01/17. */
public class TestOpenStackDriver {

  private static Properties properties;
  private static Logger log = LoggerFactory.getLogger(TestOpenStackDriver.class);
  private static OpenStack4JDriver osd;
  private static VimInstance vimInstance;

  @BeforeClass
  public static void init() throws IOException {
    properties = new Properties();
    try {
      properties.load(
          new InputStreamReader(TestOpenStackDriver.class.getResourceAsStream("/test.properties")));
    } catch (IOException e) {
      log.error("Missing test.properties file");
      throw e;
    }
    osd = new OpenStack4JDriver();
    vimInstance = getVimInstance();
  }

  @Test
  public void testAuthenticate() throws VimDriverException {
    OSClient.OSClientV3 os = osd.authenticate(vimInstance);
    log.debug("Token is: " + os.getToken());
    assert os.getToken() != null;
  }

  @Test
  public void testListImages() {
    try {
      for (NFVImage image : osd.listImages(vimInstance)) {
        log.info(image.toString());
      }
    } catch (VimDriverException e) {
      e.printStackTrace();
    }
  }

  @Test
  public void testListNetwors() {
    try {
      for (Network network : osd.listNetworks(vimInstance)) {
        log.info(network.toString());
      }
    } catch (VimDriverException e) {
      e.printStackTrace();
    }
  }

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
