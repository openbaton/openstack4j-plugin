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

import org.openbaton.catalogue.nfvo.VimInstance;
import org.openbaton.drivers.openstack4j.OpenStack4JDriver;

/**
 * Created by gca on 10/01/17.
 */
public class TestOpenStackDriver {
    public static void main(String[] args) {

        OpenStack4JDriver osd = new OpenStack4JDriver();
        VimInstance vimInstance = new VimInstance();
        vimInstance.setName("test");
        vimInstance.setAuthUrl("");
        vimInstance.setUsername("");
        vimInstance.setPassword("test");
        osd.authenticate(vimInstance);

    }
}
