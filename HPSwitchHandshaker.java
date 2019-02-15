/*
 * Copyright 2017-present Open Networking Foundation
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

package org.onosproject.drivers.hp;

import org.onosproject.openflow.controller.driver.AbstractOpenFlowSwitch;
import org.onosproject.openflow.controller.driver.SwitchDriverSubHandshakeAlreadyStarted;
import org.onosproject.openflow.controller.driver.SwitchDriverSubHandshakeCompleted;
import org.onosproject.openflow.controller.driver.SwitchDriverSubHandshakeNotStarted;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFTableFeaturesStatsRequest;
import org.projectfloodlight.openflow.protocol.OFTableFeaturesStatsReply;
import org.projectfloodlight.openflow.protocol.OFGroupMod;
import org.projectfloodlight.openflow.protocol.OFGroupType;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.types.OFGroup;
import org.projectfloodlight.openflow.types.TableId;
import java.util.concurrent.atomic.AtomicBoolean;


/**
 * HP switch handshaker.
 * Possibly compliant with all HP OF switches but tested only with HP3800.
 */
public class HPSwitchHandshaker extends AbstractOpenFlowSwitch {

    private AtomicBoolean handshakeComplete = new AtomicBoolean(false);


    @Override
    public Boolean supportNxRole() {
        return false;
    }

    @Override
    public void startDriverHandshake() {
        if (startDriverHandshakeCalled) {
            throw new SwitchDriverSubHandshakeAlreadyStarted();
        }
        startDriverHandshakeCalled = true;
        OFFlowMod fm = factory().buildFlowDelete()
                .setTableId(TableId.ALL)
                .setOutGroup(OFGroup.ANY)
                .build();

        sendHandshakeMessage(fm);

        // Send TABLE_FEATURES multipart request
        OFTableFeaturesStatsRequest ofm = factory().buildTableFeaturesStatsRequest().build();
        sendHandshakeMessage(ofm);

        OFGroupMod gm = factory().buildGroupDelete()
                .setGroup(OFGroup.ALL)
                .setGroupType(OFGroupType.ALL)
                .build();

        sendHandshakeMessage(gm);

    }

    @Override
    public boolean isDriverHandshakeComplete() {
        if (!startDriverHandshakeCalled) {
            throw new SwitchDriverSubHandshakeAlreadyStarted();
        }
        return handshakeComplete.get();
    }

    @Override
    public void processDriverHandshakeMessage(OFMessage m) {
        if (!startDriverHandshakeCalled) {
            throw new SwitchDriverSubHandshakeNotStarted();
        }
        if (handshakeComplete.get()) {
            throw new SwitchDriverSubHandshakeCompleted(m);
        }

        switch (m.getType()) {
            case STATS_REPLY:
                // Process TABLE_FEATURES multipart reply
                try {
                    OFTableFeaturesStatsReply r = (OFTableFeaturesStatsReply) m;
                    HPFeatures hpfeatures = HPFeatures.getInstance(getDpid());
                    hpfeatures.extractCriteriaFromTableFeatures(r.getEntries());
                    log.info("HP Driver Handshake: finished reading features from TABLE_FEATURES, UUID {}",
                            hpfeatures.getIdentifier().toString());
                } catch (ClassCastException e) {
                    log.warn("HP Driver Handshake: received STATS_REPLY msg, but not a TABLE_FEATURE one");
                }
                handshakeComplete.set(true);
                log.info("Handshake with device {} ended", super.getStringId());
                break;
            default:
                log.warn("HP Driver Handshake - Reply message not handled");
                break;
        }

    }

}
