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

import org.onosproject.net.flow.criteria.Criterion;
import org.onosproject.net.flow.instructions.Instruction;
import org.onosproject.net.flow.instructions.L2ModificationInstruction;
import org.onosproject.net.flow.instructions.L3ModificationInstruction;
import org.onosproject.net.flow.instructions.L4ModificationInstruction;
import org.onosproject.openflow.controller.Dpid;
import org.projectfloodlight.openflow.protocol.OFActionType;
import org.projectfloodlight.openflow.protocol.OFTableFeatureProp;
import org.projectfloodlight.openflow.protocol.OFTableFeaturePropMatch;
import org.projectfloodlight.openflow.protocol.OFTableFeaturePropWriteActions;
import org.projectfloodlight.openflow.protocol.OFTableFeaturePropWriteActionsMiss;
import org.projectfloodlight.openflow.protocol.OFTableFeaturePropApplyActions;
import org.projectfloodlight.openflow.protocol.OFTableFeaturePropApplyActionsMiss;
import org.projectfloodlight.openflow.protocol.OFTableFeaturePropApplySetfield;
import org.projectfloodlight.openflow.protocol.OFTableFeaturePropApplySetfieldMiss;
import org.projectfloodlight.openflow.protocol.OFTableFeaturePropWriteSetfield;
import org.projectfloodlight.openflow.protocol.OFTableFeaturePropWriteSetfieldMiss;
import org.projectfloodlight.openflow.protocol.OFTableFeatures;
import org.projectfloodlight.openflow.protocol.actionid.OFActionId;
import org.projectfloodlight.openflow.types.U32;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.HashSet;
import java.util.Map;
import java.util.HashMap;
import java.util.UUID;
import java.util.List;

/**
 *  A data structure to hold lists of criteria and instructions, supported in hardware or
 *  completely unsupported by the specific HP switch.
 *
 *  Objects of type HPFeatures cannot be created freely: only one object per DPID is allowed.
 */

public final class HPFeatures {

    /**
     * The Map that associates every DPID with its respective HPFeatures object.
     */
    private static Map<String, HPFeatures> instances = new HashMap<>();
    /**
     * Unique identifier for the HPFeatures object.
     */
    private final UUID identifier = UUID.randomUUID();

    /**
     * Enumeration of OpenFlow FeatureProperty types.
     */
    public static class FeatureType {
        public static final int INSTRUCTIONS        = 0;
        public static final int INSTRUCTIONS_MISS   = 1;
        public static final int NEXT_TABLES         = 2;
        public static final int NEXT_TABLES_MISS    = 3;
        public static final int WRITE_ACTIONS       = 4;
        public static final int WRITE_ACTIONS_MISS  = 5;
        public static final int APPLY_ACTIONS       = 6;
        public static final int APPLY_ACTIONS_MISS  = 7;
        public static final int MATCH               = 8;
        public static final int WILDCARDS           = 10;
        public static final int WRITE_SETFIELD      = 12;
        public static final int WRITE_SETFIELD_MISS = 13;
        public static final int APPLY_SETFIELD      = 14;
        public static final int APPLY_SETFIELD_MISS = 15;
        public static final int EXPERIMENTER        = 0xFFFE;
        public static final int EXPERIMENTER_MISS   = 0xFFFF;
    }

    /**
     * Utility class to convert from/to Project Floodlight data types.
     */
    public static class ExtractTypes {

        /**
         * Converts an OXM header (expressed as a 32-bit unsigned integer) to
         * an ONOS Criterion.
         *
         * @param header OXM header (in 32-bit unsigned integer format)
         * @return the corresponding Criterion Type.
         */
        public static Criterion.Type getCriterion(int header) {
            Logger log = LoggerFactory.getLogger("ExtractTypes");
            // Converts the header to a binary string always padded to 32 bits.
            String binString = String.format("%32s", Integer.toBinaryString(header)).replace(' ', '0');

            int classType = Integer.parseInt(binString.substring(0, 16), 2);
            if (classType == 65535) {
                log.warn("Header is {}, cannot interpret class {}", binString, binString.substring(0, 16));
                return null;
            }

            int index = Integer.parseInt(binString.substring(16, 23), 2);
            if (classType == 0 || classType == 1) {
                log.info("-------- NXM MESSAGE RECEIVED, IS {}", index);
            }

            switch (index) {
                case 0:
                    return Criterion.Type.IN_PORT;
                case 1:
                    return Criterion.Type.IN_PHY_PORT;
                case 2:
                    return Criterion.Type.METADATA;
                case 3:
                    return Criterion.Type.ETH_DST;
                case 4:
                    return Criterion.Type.ETH_SRC;
                case 5:
                    return Criterion.Type.ETH_TYPE;
                case 6:
                    return Criterion.Type.VLAN_VID;
                case 7:
                    return Criterion.Type.VLAN_PCP;
                case 8:
                    return Criterion.Type.IP_DSCP;
                case 9:
                    return Criterion.Type.IP_ECN;
                case 10:
                    return Criterion.Type.IP_PROTO;
                case 11:
                    return Criterion.Type.IPV4_SRC;
                case 12:
                    return Criterion.Type.IPV4_DST;
                case 13:
                    return Criterion.Type.TCP_SRC;
                case 14:
                    return Criterion.Type.TCP_DST;
                case 15:
                    return Criterion.Type.UDP_SRC;
                case 16:
                    return Criterion.Type.UDP_DST;
                case 17:
                    return Criterion.Type.SCTP_SRC;
                case 18:
                    return Criterion.Type.SCTP_DST;
                case 19:
                    return Criterion.Type.ICMPV4_TYPE;
                case 20:
                    return Criterion.Type.ICMPV4_CODE;
                case 21:
                    return Criterion.Type.ARP_OP;
                case 22:
                    return Criterion.Type.ARP_SPA;
                case 23:
                    return Criterion.Type.ARP_TPA;
                case 24:
                    return Criterion.Type.ARP_SHA;
                case 25:
                    return Criterion.Type.ARP_THA;
                case 26:
                    return Criterion.Type.IPV6_SRC;
                case 27:
                    return Criterion.Type.IPV6_DST;
                case 28:
                    return Criterion.Type.IPV6_FLABEL;
                case 29:
                    return Criterion.Type.ICMPV6_TYPE;
                case 30:
                    return Criterion.Type.ICMPV6_CODE;
                case 31:
                    return Criterion.Type.IPV6_ND_TARGET;
                case 32:
                    return Criterion.Type.IPV6_ND_SLL;
                case 33:
                    return Criterion.Type.IPV6_ND_TLL;
                case 34:
                    return Criterion.Type.MPLS_LABEL;
                case 35:
                    return Criterion.Type.MPLS_TC;
                case 36:
                    return Criterion.Type.MPLS_BOS;
                case 37:
                    return Criterion.Type.PBB_ISID;
                case 38:
                    return Criterion.Type.TUNNEL_ID;
                case 39:
                    return Criterion.Type.IPV6_EXTHDR;
                default:
                    log.warn("Header is {}, cannot interpret criteria with substring {}, index {}",
                            binString, binString.substring(16, 23), index);
                    return null;
            }

        }

        /**
         * Converts a Project Floodlight OFActionType to the corresponding ONOS Instruction.Type.
         * @param t the OFActionType to be converted.
         * @return an Instruction.Type object that represent the same action as the OFActionType.
         */
        public static Instruction.Type getInstruction(OFActionType t) {

            switch (t) {
                case GROUP:
                    return Instruction.Type.GROUP;
                case METER:
                    return Instruction.Type.METER;
                case OUTPUT:
                    return Instruction.Type.OUTPUT;
                case ENQUEUE:
                    return Instruction.Type.QUEUE;
                case EXPERIMENTER:
                    return Instruction.Type.EXTENSION;
                default:
                    return null;
            }
        }

        /**
         * Converts a Project Floodlight OFActionType to the corresponding ONOS
         * L2ModificationInstruction.L2SubType.
         *
         * @param t the OFActionType to be converted.
         * @return an L2ModificationInstruction.L2SubType object that represent the same action as the OFActionType.
         */
        public static L2ModificationInstruction.L2SubType getL2Subtype(OFActionType t) {
            switch (t) {
                case SET_VLAN_PCP:
                    return L2ModificationInstruction.L2SubType.VLAN_PCP;
                case DEC_MPLS_TTL:
                    return L2ModificationInstruction.L2SubType.DEC_MPLS_TTL;
                case POP_MPLS:
                    return L2ModificationInstruction.L2SubType.MPLS_POP;
                case POP_VLAN:
                    return L2ModificationInstruction.L2SubType.VLAN_POP;
                case PUSH_MPLS:
                    return L2ModificationInstruction.L2SubType.MPLS_PUSH;
                case PUSH_VLAN:
                    return L2ModificationInstruction.L2SubType.VLAN_PUSH;
                case SET_DL_DST:
                    return L2ModificationInstruction.L2SubType.ETH_DST;
                case SET_DL_SRC:
                    return L2ModificationInstruction.L2SubType.ETH_SRC;
                case SET_MPLS_LABEL:
                    return L2ModificationInstruction.L2SubType.MPLS_LABEL;
                case SET_VLAN_VID:
                    return L2ModificationInstruction.L2SubType.VLAN_ID;
                default:
                    return null;
            }
        }

        /**
         * Converts a Project Floodlight OFActionType to the corresponding ONOS
         * L3ModificationInstruction.L3SubType.
         *
         * @param t the OFActionType to be converted.
         * @return an L3ModificationInstruction.L3SubType object that represent the same action as the OFActionType.
         */
        public static L3ModificationInstruction.L3SubType getL3Subtype(OFActionType t) {
            switch (t) {
                case COPY_TTL_IN:
                    return L3ModificationInstruction.L3SubType.TTL_IN;
                case COPY_TTL_OUT:
                    return L3ModificationInstruction.L3SubType.TTL_OUT;
                case DEC_NW_TTL:
                    return L3ModificationInstruction.L3SubType.DEC_TTL;
                case SET_NW_DST:
                    return L3ModificationInstruction.L3SubType.IPV4_DST;
                case SET_NW_SRC:
                    return L3ModificationInstruction.L3SubType.IPV4_SRC;
                default:
                    return null;
            }
        }

        /**
         * Converts a Project Floodlight OFActionType to the corresponding ONOS
         * L4ModificationInstruction.L4SubType.
         *
         * @param t the OFActionType to be converted.
         * @return an L4ModificationInstruction.L4SubType object that represent the same action as the OFActionType.
         */
        public static L4ModificationInstruction.L4SubType getL4Subtype(OFActionType t) {
            switch (t) {
                case SET_TP_SRC:
                    return L4ModificationInstruction.L4SubType.TCP_SRC;
                case SET_TP_DST:
                    return L4ModificationInstruction.L4SubType.TCP_DST;
                default:
                    return null;
            }
        }

    }

    private final Logger log = LoggerFactory.getLogger(getClass());

    private boolean automaticSetup = false;

    private Set<Criterion.Type> unsupportedCriteria = new HashSet<>();
    private Set<Instruction.Type> unsupportedInstructions = new HashSet<>();
    private Set<L2ModificationInstruction.L2SubType> unsupportedL2mod = new HashSet<>();
    private Set<L3ModificationInstruction.L3SubType> unsupportedL3mod = new HashSet<>();
    private Set<L4ModificationInstruction.L4SubType> unsupportedL4mod = new HashSet<>();

    private Set<Criterion.Type> hardwareCriteria = new HashSet<>();
    private Set<Instruction.Type> hardwareInstructions = new HashSet<>();
    private Set<L2ModificationInstruction.L2SubType> hardwareInstructionsL2mod = new HashSet<>();
    private Set<L3ModificationInstruction.L3SubType> hardwareInstructionsL3mod = new HashSet<>();
    private Set<L4ModificationInstruction.L4SubType> hardwareInstructionsL4mod = new HashSet<>();

    // Private constructor when no "manual" configuration is given. It assumes that every
    // criterion and instruction is unsupported.
    private HPFeatures() {
        for (Criterion.Type criterion : Criterion.Type.values()) {
            unsupportedCriteria.add(criterion);
        }
        for (Instruction.Type instruction : Instruction.Type.values()) {
            unsupportedInstructions.add(instruction);
        }
        for (L2ModificationInstruction.L2SubType l2SubType : L2ModificationInstruction.L2SubType.values()) {
            unsupportedL2mod.add(l2SubType);
        }
        for (L3ModificationInstruction.L3SubType l3SubType : L3ModificationInstruction.L3SubType.values()) {
            unsupportedL3mod.add(l3SubType);
        }
        for (L4ModificationInstruction.L4SubType l4SubType : L4ModificationInstruction.L4SubType.values()) {
            unsupportedL4mod.add(l4SubType);
        }
    }

    // Private constructor when a "manual" configuration is given.
    private HPFeatures(Set<Criterion.Type> criteria,
                       Set<Instruction.Type> instructions,
                       Set<L2ModificationInstruction.L2SubType> l2mod,
                       Set<L3ModificationInstruction.L3SubType> l3mod,
                       Set<L4ModificationInstruction.L4SubType> l4mod) {
        unsupportedCriteria.addAll(criteria);
        unsupportedInstructions.addAll(instructions);
        unsupportedL2mod.addAll(l2mod);
        unsupportedL3mod.addAll(l3mod);
        unsupportedL4mod.addAll(l4mod);
    }

    /**
     * Returns the HPFeatures instance relative to the specific DPID.
     *
     * If no HPFeature object is associated to that DPID, a new one
     * will be created using the default constructor (no "manual"
     * configuration given).
     *
     * @param id The DPID of the current switch
     * @return The HPFeature object for that switch
     */
    public static HPFeatures getInstance(Dpid id) {
        String name = id.toString();
        HPFeatures ret = instances.get(name);
        if (ret == null) {
            ret = new HPFeatures();
            instances.put(name, ret);
        }
        return ret;
    }

    /**
     * Returns the HPFeatures instance relative to the specific DPID.
     *
     * If no HPFeature object is associated to that DPID, a new one
     * will be created using the constructor that allows to set
     * a manual configuration.
     *
     * @param id The DPID of the current switch
     * @param criteria Set of unsupported criteria
     * @param instructions Set of unsupported instructions
     * @param l2mod Set of unsupported L2 modifications
     * @param l3mod Set of unsupported L3 modifications
     * @param l4mod Set of unsupported L4 modifications
     * @return The HPFeature object for the switch
     */
    public static HPFeatures getInstance(Dpid id,
                                         Set<Criterion.Type> criteria,
                                         Set<Instruction.Type> instructions,
                                         Set<L2ModificationInstruction.L2SubType> l2mod,
                                         Set<L3ModificationInstruction.L3SubType> l3mod,
                                         Set<L4ModificationInstruction.L4SubType> l4mod) {
        String name = id.toString();
        HPFeatures ret = instances.get(name);
        if (ret == null) {
            ret = new HPFeatures(criteria, instructions, l2mod, l3mod, l4mod);
            instances.put(name, ret);
        }
        return ret;
    }

    /**
     * Clears the HPFeatures instance for a specific DPID.
     * @param id The DPID of the switch
     */
    public static void clearFeatures(Dpid id) {
        String name = id.toString();
        instances.remove(name);
    }

    // Extracts the correct sub-type of ONOS instruction (Instruction, LXModificationInstruction) starting
    // from an OFActionId object, and optionally adding it to the set of instructions supported in hardware
    private void extractActions(OFActionId id, boolean isHardware) {
        OFActionType t = id.getType();
        Instruction.Type instruction = HPFeatures.ExtractTypes.getInstruction(t);
        if (instruction == null) {
            L2ModificationInstruction.L2SubType l2 = HPFeatures.ExtractTypes.getL2Subtype(t);
            if (l2 == null) {
                L3ModificationInstruction.L3SubType l3 = HPFeatures.ExtractTypes.getL3Subtype(t);
                if (l3 == null) {
                    L4ModificationInstruction.L4SubType l4 = HPFeatures.ExtractTypes.getL4Subtype(t);
                    if (l4 == null) {
                        log.warn("OF Action Type {} not supported", t);
                    } else {
                        if (isHardware) {
                            addHardwareInstruction(Instruction.Type.L4MODIFICATION);
                            addHardwareL4Mod(l4);
                        }
                        addSupportedInstruction(Instruction.Type.L4MODIFICATION);
                        addL4Mod(l4);
                    }
                } else {
                    if (isHardware) {
                        addHardwareInstruction(Instruction.Type.L3MODIFICATION);
                        addHardwareL3Mod(l3);
                    }
                    addSupportedInstruction(Instruction.Type.L3MODIFICATION);
                    addL3Mod(l3);
                }
            } else {
                if (isHardware) {
                    addHardwareInstruction(Instruction.Type.L2MODIFICATION);
                    addHardwareL2Mod(l2);
                }
                addSupportedInstruction(Instruction.Type.L2MODIFICATION);
                addL2Mod(l2);
            }
        } else {
            if (isHardware) {
                addHardwareInstruction(instruction);
            }
            addSupportedInstruction(instruction);
        }
    }

    // Reads features for a single table
    private void extractCriteriaForTable(List<OFTableFeatureProp> featurePropList, boolean isHardware) {

        for (OFTableFeatureProp featureProp: featurePropList) {
            switch (featureProp.getType()) {
                case FeatureType.MATCH:
                    OFTableFeaturePropMatch propMatch = (OFTableFeaturePropMatch) featureProp;
                    checkOxms(isHardware, propMatch.getOxmIds());
                    break;
                case FeatureType.WRITE_ACTIONS:
                    OFTableFeaturePropWriteActions writeActions = (OFTableFeaturePropWriteActions) featureProp;
                    for (OFActionId id: writeActions.getActionIds()) {
                        extractActions(id, isHardware);
                    }
                    break;
                case FeatureType.APPLY_ACTIONS:
                    OFTableFeaturePropApplyActions applyActions = (OFTableFeaturePropApplyActions) featureProp;
                    for (OFActionId id: applyActions.getActionIds()) {
                        extractActions(id, isHardware);
                    }
                    break;
                case FeatureType.WRITE_ACTIONS_MISS:
                    OFTableFeaturePropWriteActionsMiss writeActionsMiss =
                            (OFTableFeaturePropWriteActionsMiss) featureProp;
                    for (OFActionId id: writeActionsMiss.getActionIds()) {
                        extractActions(id, isHardware);
                    }
                    break;
                case FeatureType.APPLY_ACTIONS_MISS:
                    OFTableFeaturePropApplyActionsMiss applyActionsMiss =
                            (OFTableFeaturePropApplyActionsMiss) featureProp;
                    for (OFActionId id: applyActionsMiss.getActionIds()) {
                        extractActions(id, isHardware);
                    }
                    break;
                /*case FeatureType.WILDCARDS:
                    OFTableFeaturePropWildcards wildcards = (OFTableFeaturePropWildcards) featureProp;
                    checkOxms(isHardware, wildcards.getOxmIds());
                    break;*/
                case FeatureType.APPLY_SETFIELD:
                    OFTableFeaturePropApplySetfield applySetfield = (OFTableFeaturePropApplySetfield) featureProp;
                    checkFields(isHardware, applySetfield.getOxmIds());
                    break;
                case FeatureType.APPLY_SETFIELD_MISS:
                    OFTableFeaturePropApplySetfieldMiss applySetfieldMiss =
                            (OFTableFeaturePropApplySetfieldMiss) featureProp;
                    checkFields(isHardware, applySetfieldMiss.getOxmIds());
                    break;
                case FeatureType.WRITE_SETFIELD:
                    OFTableFeaturePropWriteSetfield writeSetfield = (OFTableFeaturePropWriteSetfield) featureProp;
                    checkFields(isHardware, writeSetfield.getOxmIds());
                    break;
                case FeatureType.WRITE_SETFIELD_MISS:
                    OFTableFeaturePropWriteSetfieldMiss writeSetfieldMiss =
                            (OFTableFeaturePropWriteSetfieldMiss) featureProp;
                    checkFields(isHardware, writeSetfieldMiss.getOxmIds());
                    break;
                default:
                    log.warn("Ignoring feature type {}", featureProp);
                    break;

            }
        }

    }

    // Extracts and adds criteria from a list of OXM ids.
    private void checkOxms(boolean isHardware, List<U32> oxmIds) {
        for (U32 type : oxmIds) {
            Criterion.Type match = ExtractTypes.getCriterion(type.getRaw());
            if (match != null) {
                if (isHardware) {
                    addHardwareCriterion(match);
                }
                addSupportedCriterion(match);
            }
        }
    }

    private void checkFields(boolean isHardware, List<U32> oxmIds) {
        for (U32 type : oxmIds) {
            Criterion.Type extracted = ExtractTypes.getCriterion(type.getRaw());
            if (extracted == null) {
                continue;
            }
            switch (extracted) {
                case ARP_OP:
                    addSupportedInstruction(Instruction.Type.L3MODIFICATION);
                    addL3Mod(L3ModificationInstruction.L3SubType.ARP_OP);
                    if (isHardware) {
                        addHardwareL3Mod(L3ModificationInstruction.L3SubType.ARP_OP);
                        addHardwareInstruction(Instruction.Type.L3MODIFICATION);
                    }
                    break;
                case ARP_SHA:
                    addSupportedInstruction(Instruction.Type.L3MODIFICATION);
                    addL3Mod(L3ModificationInstruction.L3SubType.ARP_SHA);
                    if (isHardware) {
                        addHardwareL3Mod(L3ModificationInstruction.L3SubType.ARP_SHA);
                        addHardwareInstruction(Instruction.Type.L3MODIFICATION);
                    }
                    break;
                case ARP_SPA:
                    addSupportedInstruction(Instruction.Type.L3MODIFICATION);
                    addL3Mod(L3ModificationInstruction.L3SubType.ARP_SPA);
                    if (isHardware) {
                        addHardwareL3Mod(L3ModificationInstruction.L3SubType.ARP_SPA);
                        addHardwareInstruction(Instruction.Type.L3MODIFICATION);
                    }
                    break;
                case ETH_SRC:
                    addSupportedInstruction(Instruction.Type.L2MODIFICATION);
                    addL2Mod(L2ModificationInstruction.L2SubType.ETH_SRC);
                    if (isHardware) {
                        addHardwareL2Mod(L2ModificationInstruction.L2SubType.ETH_SRC);
                        addHardwareInstruction(Instruction.Type.L2MODIFICATION);
                    }
                    break;
                case ETH_DST:
                    addSupportedInstruction(Instruction.Type.L2MODIFICATION);
                    addL2Mod(L2ModificationInstruction.L2SubType.ETH_DST);
                    if (isHardware) {
                        addHardwareL2Mod(L2ModificationInstruction.L2SubType.ETH_DST);
                        addHardwareInstruction(Instruction.Type.L2MODIFICATION);
                    }
                    break;
                case IPV4_DST:
                    addSupportedInstruction(Instruction.Type.L3MODIFICATION);
                    addL3Mod(L3ModificationInstruction.L3SubType.IPV4_DST);
                    if (isHardware) {
                        addHardwareL3Mod(L3ModificationInstruction.L3SubType.IPV4_DST);
                        addHardwareInstruction(Instruction.Type.L3MODIFICATION);
                    }
                    break;
                case IPV4_SRC:
                    addSupportedInstruction(Instruction.Type.L3MODIFICATION);
                    addL3Mod(L3ModificationInstruction.L3SubType.IPV4_SRC);
                    if (isHardware) {
                        addHardwareL3Mod(L3ModificationInstruction.L3SubType.IPV4_SRC);
                        addHardwareInstruction(Instruction.Type.L3MODIFICATION);
                    }
                    break;
                case IPV6_DST:
                    addSupportedInstruction(Instruction.Type.L3MODIFICATION);
                    addL3Mod(L3ModificationInstruction.L3SubType.IPV6_DST);
                    if (isHardware) {
                        addHardwareL3Mod(L3ModificationInstruction.L3SubType.IPV6_DST);
                        addHardwareInstruction(Instruction.Type.L3MODIFICATION);
                    }
                    break;
                case IPV6_FLABEL:
                    addSupportedInstruction(Instruction.Type.L3MODIFICATION);
                    addL3Mod(L3ModificationInstruction.L3SubType.IPV6_FLABEL);
                    if (isHardware) {
                        addHardwareL3Mod(L3ModificationInstruction.L3SubType.IPV6_FLABEL);
                        addHardwareInstruction(Instruction.Type.L3MODIFICATION);
                    }
                    break;
                case IPV6_SRC:
                    addSupportedInstruction(Instruction.Type.L3MODIFICATION);
                    addL3Mod(L3ModificationInstruction.L3SubType.IPV6_SRC);
                    if (isHardware) {
                        addHardwareL3Mod(L3ModificationInstruction.L3SubType.IPV6_SRC);
                        addHardwareInstruction(Instruction.Type.L3MODIFICATION);
                    }
                    break;
                case METADATA:
                    addSupportedInstruction(Instruction.Type.METADATA);
                    if (isHardware) {
                        addHardwareInstruction(Instruction.Type.METADATA);
                    }
                    break;
                case EXTENSION:
                    addSupportedInstruction(Instruction.Type.EXTENSION);
                    if (isHardware) {
                        addHardwareInstruction(Instruction.Type.EXTENSION);
                    }
                    break;
                case MPLS_BOS:
                    addSupportedInstruction(Instruction.Type.L2MODIFICATION);
                    addL2Mod(L2ModificationInstruction.L2SubType.MPLS_BOS);
                    if (isHardware) {
                        addHardwareL2Mod(L2ModificationInstruction.L2SubType.MPLS_BOS);
                        addHardwareInstruction(Instruction.Type.L2MODIFICATION);
                    }
                    break;
                case MPLS_LABEL:
                    addSupportedInstruction(Instruction.Type.L2MODIFICATION);
                    addL2Mod(L2ModificationInstruction.L2SubType.MPLS_LABEL);
                    if (isHardware) {
                        addHardwareL2Mod(L2ModificationInstruction.L2SubType.MPLS_LABEL);
                        addHardwareInstruction(Instruction.Type.L2MODIFICATION);
                    }
                    break;
                case ODU_SIGID:
                    addSupportedInstruction(Instruction.Type.L1MODIFICATION);
                    if (isHardware) {
                        addHardwareInstruction(Instruction.Type.L1MODIFICATION);
                    }
                    break;
                case PROTOCOL_INDEPENDENT:
                    addSupportedInstruction(Instruction.Type.PROTOCOL_INDEPENDENT);
                    if (isHardware) {
                        addHardwareInstruction(Instruction.Type.PROTOCOL_INDEPENDENT);
                    }
                    break;
                case TCP_DST:
                    addSupportedInstruction(Instruction.Type.L4MODIFICATION);
                    addL4Mod(L4ModificationInstruction.L4SubType.TCP_DST);
                    if (isHardware) {
                        addHardwareL4Mod(L4ModificationInstruction.L4SubType.TCP_DST);
                        addHardwareInstruction(Instruction.Type.L4MODIFICATION);
                    }
                    break;
                case TCP_SRC:
                    addSupportedInstruction(Instruction.Type.L4MODIFICATION);
                    addL4Mod(L4ModificationInstruction.L4SubType.TCP_SRC);
                    if (isHardware) {
                        addHardwareL4Mod(L4ModificationInstruction.L4SubType.TCP_SRC);
                        addHardwareInstruction(Instruction.Type.L4MODIFICATION);
                    }
                    break;
                case TUNNEL_ID:
                    addSupportedInstruction(Instruction.Type.L2MODIFICATION);
                    addL2Mod(L2ModificationInstruction.L2SubType.TUNNEL_ID);
                    if (isHardware) {
                        addHardwareL2Mod(L2ModificationInstruction.L2SubType.TUNNEL_ID);
                        addHardwareInstruction(Instruction.Type.L2MODIFICATION);
                    }
                    break;
                case UDP_DST:
                    addSupportedInstruction(Instruction.Type.L4MODIFICATION);
                    addL4Mod(L4ModificationInstruction.L4SubType.UDP_DST);
                    if (isHardware) {
                        addHardwareL4Mod(L4ModificationInstruction.L4SubType.UDP_DST);
                        addHardwareInstruction(Instruction.Type.L4MODIFICATION);
                    }
                    break;
                case UDP_SRC:
                    addSupportedInstruction(Instruction.Type.L4MODIFICATION);
                    addL4Mod(L4ModificationInstruction.L4SubType.UDP_SRC);
                    if (isHardware) {
                        addHardwareL4Mod(L4ModificationInstruction.L4SubType.UDP_SRC);
                        addHardwareInstruction(Instruction.Type.L4MODIFICATION);
                    }
                    break;
                case VLAN_PCP:
                    addSupportedInstruction(Instruction.Type.L2MODIFICATION);
                    addL2Mod(L2ModificationInstruction.L2SubType.VLAN_PCP);
                    if (isHardware) {
                        addHardwareL2Mod(L2ModificationInstruction.L2SubType.VLAN_PCP);
                        addHardwareInstruction(Instruction.Type.L2MODIFICATION);
                    }
                    break;
                case VLAN_VID:
                    addSupportedInstruction(Instruction.Type.L2MODIFICATION);
                    addL2Mod(L2ModificationInstruction.L2SubType.VLAN_ID);
                    if (isHardware) {
                        addHardwareL2Mod(L2ModificationInstruction.L2SubType.VLAN_ID);
                        addHardwareInstruction(Instruction.Type.L2MODIFICATION);
                    }
                    break;
                default:
                    String name = (ExtractTypes.getCriterion(type.getRaw()) != null) ?
                            ExtractTypes.getCriterion(type.getRaw()).name() : "null";
                    log.debug("Unsupported action {}", name);
            }
        }
    }

    /**
     * Extracts features from a list of OFTableFeatures.
     *
     * @param tableFeaturesList the list of OFTableFeatures received by the switch.
     */
    public void extractCriteriaFromTableFeatures(List<OFTableFeatures> tableFeaturesList) {
        for (OFTableFeatures tableFeatures: tableFeaturesList) {
            boolean isHardware = false;

            switch (tableFeatures.getTableId().getValue()) {
                case AbstractHPPipeline.HP_HARDWARE_TABLE:
                    isHardware = true;
                default:
                    extractCriteriaForTable(tableFeatures.getProperties(), isHardware);

            }

        }

        automaticSetup = true;
    }

    // Collection of getter and setter methods

    public void addSupportedCriterion(Criterion.Type criterion) {
        unsupportedCriteria.remove(criterion);
    }

    public void addSupportedInstruction(Instruction.Type instruction) {
        unsupportedInstructions.remove(instruction);
    }

    public void addL2Mod(L2ModificationInstruction.L2SubType l2mod) {
        unsupportedL2mod.remove(l2mod);
    }

    public void addL3Mod(L3ModificationInstruction.L3SubType l3mod) {
        unsupportedL3mod.remove(l3mod);
    }

    public void addL4Mod(L4ModificationInstruction.L4SubType l4mod) {
        unsupportedL4mod.remove(l4mod);
    }

    public void addHardwareCriterion(Criterion.Type criterion) {
        hardwareCriteria.add(criterion);
    }

    public void addHardwareInstruction(Instruction.Type instruction) {
        hardwareInstructions.add(instruction);
    }

    public void addHardwareL2Mod(L2ModificationInstruction.L2SubType l2mod) {
        hardwareInstructionsL2mod.add(l2mod);
    }

    public void addHardwareL3Mod(L3ModificationInstruction.L3SubType l3mod) {
        hardwareInstructionsL3mod.add(l3mod);
    }

    public void addHardwareL4Mod(L4ModificationInstruction.L4SubType l4mod) {
        hardwareInstructionsL4mod.add(l4mod);
    }

    public Set<Criterion.Type> getUnsupportedCriteria() {
        return unsupportedCriteria;
    }

    public Set<Instruction.Type> getUnsupportedInstructions() {
        return unsupportedInstructions;
    }

    public Set<L2ModificationInstruction.L2SubType> getUnsupportedL2mod() {
        return unsupportedL2mod;
    }

    public Set<L3ModificationInstruction.L3SubType> getUnsupportedL3mod() {
        return unsupportedL3mod;
    }

    public Set<L4ModificationInstruction.L4SubType> getUnsupportedL4mod() {
        return unsupportedL4mod;
    }

    public Set<Criterion.Type> getHardwareCriteria() {
        return hardwareCriteria;
    }

    public Set<Instruction.Type> getHardwareInstructions() {
        return hardwareInstructions;
    }

    public Set<L2ModificationInstruction.L2SubType> getHardwareInstructionsL2mod() {
        return hardwareInstructionsL2mod;
    }

    public Set<L3ModificationInstruction.L3SubType> getHardwareInstructionsL3mod() {
        return hardwareInstructionsL3mod;
    }

    public Set<L4ModificationInstruction.L4SubType> getHardwareInstructionsL4mod() {
        return hardwareInstructionsL4mod;
    }

    public boolean isAutomaticSetup() {
        return automaticSetup;
    }

    public UUID getIdentifier() {
        return identifier;
    }
}
