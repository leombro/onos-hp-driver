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

import org.onlab.packet.Ethernet;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.criteria.EthCriterion;
import org.onosproject.net.flow.criteria.EthTypeCriterion;
import org.onosproject.net.flow.criteria.IPCriterion;
import org.onosproject.net.flow.criteria.PortCriterion;
import org.onosproject.net.flow.criteria.VlanIdCriterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.L2ModificationInstruction;
import org.onosproject.net.flow.instructions.L3ModificationInstruction;
import org.onosproject.net.flow.instructions.L4ModificationInstruction;
import org.onosproject.net.flow.instructions.Instructions;
import org.onosproject.net.flowobjective.FilteringObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.slf4j.Logger;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.slf4j.LoggerFactory.getLogger;

/**
 * Driver for HP hybrid switches employing V1 hardware module.
 *
 * - HP2910
 * - HP3500, tested
 * - HP5400, depends on switch configuration if "allow-v1-modules" it operates as V1
 * - HP6200
 * - HP6600
 * - HP8200, depends on switch configuration if "allow-v1-modules" it operates as V1
 *
 * Refer to the device manual to check unsupported features and features supported in hardware
 */

public class HPPipelineV1 extends AbstractHPPipeline {

    private Logger log = getLogger(getClass());

    @Override
    protected FlowRule.Builder setDefaultTableIdForFlowObjective(FlowRule.Builder ruleBuilder) {
        log.warn("HP V1 Driver - Setting default table id to software table {}", HP_SOFTWARE_TABLE);

        return ruleBuilder.forTable(HP_SOFTWARE_TABLE);
    }

    @Override
    protected void initUnSupportedFeatures() {
        // "Manually" initialize unsupported features
        Set<Criterion.Type> currentUnsuppCriteria = new HashSet<>();
        Set<Instruction.Type> currentUnsuppInstruction = new HashSet<>();
        Set<L2ModificationInstruction.L2SubType> currentUnsuppL2 = new HashSet<>();
        Set<L3ModificationInstruction.L3SubType> currentUnsuppL3 = new HashSet<>();


        //Initialize unsupported criteria
        currentUnsuppCriteria.add(Criterion.Type.METADATA);
        currentUnsuppCriteria.add(Criterion.Type.IP_ECN);
        currentUnsuppCriteria.add(Criterion.Type.SCTP_SRC);
        currentUnsuppCriteria.add(Criterion.Type.SCTP_SRC_MASKED);
        currentUnsuppCriteria.add(Criterion.Type.SCTP_DST);
        currentUnsuppCriteria.add(Criterion.Type.SCTP_DST_MASKED);
        currentUnsuppCriteria.add(Criterion.Type.IPV6_ND_SLL);
        currentUnsuppCriteria.add(Criterion.Type.IPV6_ND_TLL);
        currentUnsuppCriteria.add(Criterion.Type.MPLS_LABEL);
        currentUnsuppCriteria.add(Criterion.Type.MPLS_TC);
        currentUnsuppCriteria.add(Criterion.Type.MPLS_BOS);
        currentUnsuppCriteria.add(Criterion.Type.PBB_ISID);
        currentUnsuppCriteria.add(Criterion.Type.TUNNEL_ID);
        currentUnsuppCriteria.add(Criterion.Type.IPV6_EXTHDR);

        //Initialize unsupported instructions
        currentUnsuppInstruction.add(Instruction.Type.QUEUE);
        currentUnsuppInstruction.add(Instruction.Type.METADATA);
        currentUnsuppInstruction.add(Instruction.Type.L0MODIFICATION);
        currentUnsuppInstruction.add(Instruction.Type.L1MODIFICATION);
        currentUnsuppInstruction.add(Instruction.Type.PROTOCOL_INDEPENDENT);
        currentUnsuppInstruction.add(Instruction.Type.EXTENSION);
        currentUnsuppInstruction.add(Instruction.Type.STAT_TRIGGER);

        //Initialize unsupported L2MODIFICATION actions
        currentUnsuppL2.add(L2ModificationInstruction.L2SubType.MPLS_PUSH);
        currentUnsuppL2.add(L2ModificationInstruction.L2SubType.MPLS_POP);
        currentUnsuppL2.add(L2ModificationInstruction.L2SubType.MPLS_LABEL);
        currentUnsuppL2.add(L2ModificationInstruction.L2SubType.MPLS_BOS);
        currentUnsuppL2.add(L2ModificationInstruction.L2SubType.DEC_MPLS_TTL);

        //Initialize unsupported L3MODIFICATION actions
        currentUnsuppL3.add(L3ModificationInstruction.L3SubType.TTL_IN);
        currentUnsuppL3.add(L3ModificationInstruction.L3SubType.TTL_OUT);
        currentUnsuppL3.add(L3ModificationInstruction.L3SubType.DEC_TTL);

        //All L4MODIFICATION actions are supported


        // If an HPFeatures object has already been created for this dpid, then
        // return it. Otherwise, build it using the manually-defined features
        HPFeatures hpFeatures = HPFeatures.getInstance(dpid,
                currentUnsuppCriteria,
                currentUnsuppInstruction,
                currentUnsuppL2,
                currentUnsuppL3,
                Collections.emptySet());
        log.info("HP V1 Driver - Read features for UUID {}", hpFeatures.getIdentifier().toString());

        unsupportedCriteria.addAll(hpFeatures.getUnsupportedCriteria());
        unsupportedInstructions.addAll(hpFeatures.getUnsupportedInstructions());
        unsupportedL2mod.addAll(hpFeatures.getUnsupportedL2mod());
        unsupportedL3mod.addAll(hpFeatures.getUnsupportedL3mod());
        unsupportedL4mod.addAll(hpFeatures.getUnsupportedL4mod());

        // Uncomment to check correctness of automatically-defined unsupported criteria.

        log.info("HP V1 Driver - Unsupported criteria ------------------------------------------");
        for (Criterion.Type c: unsupportedCriteria) {
            log.info("  - {}", c.name());
        }
        log.info("HP V1 Driver - Unsupported instructions --------------------------------------");
        for (Instruction.Type c: unsupportedInstructions) {
            log.info("  - {}", c.name());
        }
        log.info("HP V1 Driver - Unsupported L2Mod ---------------------------------------------");
        for (L2ModificationInstruction.L2SubType c: unsupportedL2mod) {
            log.info("  - {}", c.name());
        }
        log.info("HP V1 Driver - Unsupported L3Mod ---------------------------------------------");
        for (L3ModificationInstruction.L3SubType c: unsupportedL3mod) {
            log.info("  - {}", c.name());
        }
        log.info("HP V1 Driver - Unsupported L4Mod ---------------------------------------------");
        for (L4ModificationInstruction.L4SubType c: unsupportedL4mod) {
            log.info("  - {}", c.name());
        }

    }

    @Override
    protected void initHardwareCriteria() {
        log.info("HP V1 Driver - Initializing hardware supported criteria");

        // Get the HPFeatures object for this dpid
        HPFeatures hpFeatures = HPFeatures.getInstance(dpid);

        if (!hpFeatures.isAutomaticSetup()) {
            // Manual configuration
            hardwareCriteria.add(Criterion.Type.IN_PORT);
            hardwareCriteria.add(Criterion.Type.VLAN_VID);

            //Match in hardware is supported only for ETH_TYPE == IPv4 (0x0800)
            hardwareCriteria.add(Criterion.Type.ETH_TYPE);

            hardwareCriteria.add(Criterion.Type.IPV4_SRC);
            hardwareCriteria.add(Criterion.Type.IPV4_DST);
            hardwareCriteria.add(Criterion.Type.IP_PROTO);
            hardwareCriteria.add(Criterion.Type.IP_DSCP);
            hardwareCriteria.add(Criterion.Type.TCP_SRC);
            hardwareCriteria.add(Criterion.Type.TCP_DST);
        } else {
            log.debug("HP V1 Driver: using TABLE_FEATURES hardware criteria");
            hardwareCriteria.addAll(hpFeatures.getHardwareCriteria());
        }

        log.info("HP V1 Driver - Hardware criteria ------------------------------------------");
        for (Criterion.Type c: hardwareCriteria) {
            log.info(" V1 - {}", c.name());
        }

    }

    @Override
    protected void initHardwareInstructions() {
        log.info("HP V1 Driver - Initializing hardware supported instructions");

        // Get the HPFeatures object for this dpid
        HPFeatures hpFeatures = HPFeatures.getInstance(dpid);

        if (!hpFeatures.isAutomaticSetup()) {
            // Manual configuration
            hardwareInstructions.add(Instruction.Type.OUTPUT);

            // Manual configuration
            hardwareInstructions.add(Instruction.Type.L2MODIFICATION);
            hardwareInstructionsL2mod.add(L2ModificationInstruction.L2SubType.VLAN_PCP);
        } else {
            log.debug("HP V1 Driver: using TABLE_FEATURES hardware supported instructions");
            hardwareInstructions.addAll(hpFeatures.getHardwareInstructions());
            hardwareInstructionsL2mod.addAll(hpFeatures.getHardwareInstructionsL2mod());
        }

        hardwareInstructionsL3mod.addAll(hpFeatures.getHardwareInstructionsL3mod());
        hardwareInstructionsL4mod.addAll(hpFeatures.getHardwareInstructionsL4mod());

        log.info("HP V1 Driver - Hardware instruction ---------------------------------------");
        for (Instruction.Type c: hardwareInstructions) {
            log.info(" V1 - {}", c.name());
        }
        log.info("HP V1 Driver - Hardware L2 ------------------------------------------------");
        for (L2ModificationInstruction.L2SubType c: hardwareInstructionsL2mod) {
            log.info(" V1 - {}", c.name());
        }
        log.info("HP V1 Driver - Hardware L3 ------------------------------------------------");
        for (L3ModificationInstruction.L3SubType c: hardwareInstructionsL3mod) {
            log.info(" V1 - {}", c.name());
        }
        log.info("HP V1 Driver - Hardware L4 ------------------------------------------------");
        for (L4ModificationInstruction.L4SubType c: hardwareInstructionsL4mod) {
            log.info(" V1 - {}", c.name());
        }

    }

    //Return TRUE if ForwardingObjective fwd includes unsupported features
    @Override
    protected boolean checkUnSupportedFeatures(ForwardingObjective fwd) {
        boolean unsupportedFeatures = false;

        for (Criterion criterion : fwd.selector().criteria()) {
            if (this.unsupportedCriteria.contains(criterion.type())) {
                log.warn("HP V1 Driver - unsupported criteria {}", criterion.type());

                unsupportedFeatures = true;
            }
        }

        for (Instruction instruction : fwd.treatment().allInstructions()) {
            if (this.unsupportedInstructions.contains(instruction.type())) {
                log.warn("HP V1 Driver - unsupported instruction {}", instruction.type());

                unsupportedFeatures = true;
            }

            if (instruction.type() == Instruction.Type.L2MODIFICATION) {
                if (this.unsupportedL2mod.contains(((L2ModificationInstruction) instruction).subtype())) {
                    log.warn("HP V1 Driver - unsupported L2MODIFICATION instruction {}",
                            ((L2ModificationInstruction) instruction).subtype());

                    unsupportedFeatures = true;
                }
            }

            if (instruction.type() == Instruction.Type.L3MODIFICATION) {
                if (this.unsupportedL3mod.contains(((L3ModificationInstruction) instruction).subtype())) {
                    log.warn("HP V1 Driver - unsupported L3MODIFICATION instruction {}",
                            ((L3ModificationInstruction) instruction).subtype());

                    unsupportedFeatures = true;
                }
            }
        }

        return unsupportedFeatures;
    }

    @Override
    protected int getHwMatchesAndBuild(ForwardingObjective fwd, TrafficSelector.Builder selectorBuilder) {
        int count = 0;

        log.info("HP V1 Driver - Checking possible HARDWARE match for a rule to be installed in SOFTWARE");

        for (Criterion criterion : fwd.selector().criteria()) {

            if (hardwareCriteria.contains(criterion.type())) {
                if (criterion.type() == Criterion.Type.ETH_TYPE) {
                    if (((EthTypeCriterion) criterion).ethType().toShort() == Ethernet.TYPE_IPV4) {
                        count++;
                        selectorBuilder.add(criterion);
                    }
                } else if (criterion.type() == Criterion.Type.IN_PORT) {
                    for (Criterion requiredCriterion : fwd.selector().criteria()) {
                        if (requiredCriterion.type() == Criterion.Type.ETH_TYPE) {
                            count++;
                            selectorBuilder.add(criterion);
                            break;
                        }
                    }
                } else {
                    count++;
                    selectorBuilder.add(criterion);
                }
            }

        }

        return count;
    }

    @Override
    protected int tableIdForForwardingObjective(ForwardingObjective fwd) {
        boolean hardwareProcess = true;

        log.debug("HP V1 Driver - Evaluating the ForwardingObjective for proper TableID");

        //Check criteria supported in hardware
        for (Criterion criterion : fwd.selector().criteria()) {

            if (!this.hardwareCriteria.contains(criterion.type())) {
                log.warn("HP V1 Driver - criterion {} only supported in SOFTWARE", criterion.type());

                hardwareProcess = false;
                break;
            }

            //HP3500 supports hardware match on ETH_TYPE only with value TYPE_IPV4
            if (criterion.type() == Criterion.Type.ETH_TYPE) {

                if (((EthTypeCriterion) criterion).ethType().toShort() != Ethernet.TYPE_IPV4) {
                    log.warn("HP V1 Driver - only ETH_TYPE == IPv4 (0x0800) is supported in hardware");

                    hardwareProcess = false;
                    break;
                }
            }

            //HP3500 supports IN_PORT criterion in hardware only if associated with ETH_TYPE criterion
            if (criterion.type() == Criterion.Type.IN_PORT) {
                hardwareProcess = false;

                for (Criterion requiredCriterion : fwd.selector().criteria()) {
                    if (requiredCriterion.type() == Criterion.Type.ETH_TYPE) {
                        hardwareProcess = true;
                    }
                }

                if (!hardwareProcess) {
                    log.warn("HP V1 Driver - IN_PORT criterion without ETH_TYPE is not supported in hardware");

                    break;
                }
            }

        }

        //Check if a CLEAR action is included
        if (fwd.treatment().clearedDeferred()) {
            log.warn("HP V1 Driver - CLEAR action only supported in SOFTWARE");

            hardwareProcess = false;
        }

        //If criteria can be processed in hardware, then check treatment
        if (hardwareProcess) {

            for (Instruction instruction : fwd.treatment().allInstructions()) {

                //Check if the instruction type is contained in the hardware instruction
                if (!this.hardwareInstructions.contains(instruction.type())) {
                    log.warn("HP V1 Driver - instruction {} only supported in SOFTWARE", instruction.type());

                    hardwareProcess = false;
                    break;
                }

                /* All GROUP types are supported in software by V2 switches
                 */

                /* If output is CONTROLLER_PORT the flow entry could be installed in hardware
                 * but is anyway processed in software because openflow header has to be added
                 */
                if (instruction.type() == Instruction.Type.OUTPUT) {
                    if (((Instructions.OutputInstruction) instruction).port() == PortNumber.CONTROLLER) {
                        log.warn("HP V1 Driver - Forwarding to CONTROLLER only supported in software");

                        hardwareProcess = false;
                        break;
                    }
                }

                /* Only L2MODIFICATION supported in hardware is MODIFY VLAN_PRIORITY.
                 * Check if the specific L2MODIFICATION.subtype is supported in hardware
                 */
                if (instruction.type() == Instruction.Type.L2MODIFICATION) {

                    if (!this.hardwareInstructionsL2mod.contains(((L2ModificationInstruction) instruction).subtype())) {
                        log.warn("HP V1 Driver - L2MODIFICATION.subtype {} only supported in SOFTWARE",
                                ((L2ModificationInstruction) instruction).subtype());

                        hardwareProcess = false;
                        break;
                    }

                }
            }
        }

        if (hardwareProcess) {
            log.warn("HP V1 Driver - This flow rule is supported in HARDWARE");
            return HP_HARDWARE_TABLE;
        } else {
            //TODO: create a specific flow in table 100 to redirect selected traffic on table 200



            log.warn("HP V1 Driver - This flow rule is only supported in SOFTWARE");
            return HP_SOFTWARE_TABLE;
        }

    }

    @Override
    public void filter(FilteringObjective filter) {
        log.error("HP V1 Driver - Unsupported FilteringObjective: filtering method send");
    }

    @Override
    protected FlowRule.Builder processEthFilter(FilteringObjective filt, EthCriterion eth, PortCriterion port) {
        log.error("HP V1 Driver - Unsupported FilteringObjective: processEthFilter invoked");
        return null;
    }

    @Override
    protected FlowRule.Builder processVlanFilter(FilteringObjective filt, VlanIdCriterion vlan, PortCriterion port) {
        log.error("HP V1 Driver - Unsupported FilteringObjective: processVlanFilter invoked");
        return null;
    }

    @Override
    protected FlowRule.Builder processIpFilter(FilteringObjective filt, IPCriterion ip, PortCriterion port) {
        log.error("HP V1 Driver - Unsupported FilteringObjective: processIpFilter invoked");
        return null;
    }
}

