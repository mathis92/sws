/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.acl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.apache.log4j.spi.LoggerFactory;
import org.jnetpcap.packet.PcapPacket;
import org.slf4j.Logger;
import sk.mathis.stuba.swist.analysers.Analyser;
import sk.mathis.stuba.swist.equip.ProtocolItem;
import sk.mathis.stuba.swist.equip.DataHelpers;
import sk.mathis.stuba.swist.equip.DataTypeHelper;

/**
 *
 * @author martinhudec
 */
public class AcccessList {

    private CopyOnWriteArrayList<AccesListItem> aclIn;
    private Analyser analyzer;
    private CopyOnWriteArrayList<AccesListItem> aclOut;
    private Logger logger = org.slf4j.LoggerFactory.getLogger(AcccessList.class);

    public AcccessList() {
        aclIn = new CopyOnWriteArrayList<>();
        aclOut = new CopyOnWriteArrayList<>();
        analyzer = new Analyser();
    }

    public void addAclItem(AccesListItem item, String direction) {
        switch (direction) {
            case "IN":
                aclIn.add(item);
                break;
            case "OUT":
                aclOut.add(item);
                break;
        }
    }

    public void repairPriorities(CopyOnWriteArrayList<AccesListItem> acl, Integer position) {
        for (int i = position + 1; i < acl.size(); i++) {
            acl.get(i).setPriority(acl.get(i).getPriority() - 1);
        }
    }

    public void deleteAclItem(Integer priority, String direction) {
        logger.debug(priority + " " + direction);
        switch (direction) {
            case "IN":
                aclIn.remove((int) priority);
                this.repairPriorities(aclIn, priority);
                break;
            case "OUT":
                aclOut.remove((int) priority);
                this.repairPriorities(aclOut, priority);
                break;
        }
    }

    public Boolean checkAclMAC(PcapPacket packet, String direction) {
        Boolean passed = false;
        analyzer.analyzePacket(packet);
        for (AccesListItem ali : ((direction.equals("IN")) ? aclIn : aclOut)) {
            if (Arrays.equals(ali.getSrcMacAddress(), analyzer.getFrame().getSrcMacAddress()) || ali.getSrcMacAddress() == null) {
                if (Arrays.equals(ali.getDstMacAddress(), analyzer.getFrame().getDstMacAddress()) || ali.getDstMacAddress() == null) {
                    passed = true;
                }
            }
        }
        return passed;
    }

    public Boolean checkAcl(PcapPacket packet, String direction) {
        analyzer.analyzePacket(packet);
        logger.debug("----------------> " + ((direction.equals("IN") ? "FOO" : "BAR")));
        
        for (AccesListItem ali : ((direction.equals("IN")) ? aclIn : aclOut)) {
            logger.debug("------------------------------> MEOW");
            if (Arrays.equals(ali.getSrcMacAddress(), analyzer.getFrame().getSrcMacAddress()) || ali.getSrcMacAddress() == null) {
                logger.debug("------------------------------> A");
                logger.debug("smer " + direction + " src mac adresa " + DataTypeHelper.macAdressConvertor(analyzer.getFrame().getSrcMacAddress()) + " dst mac addressa " + DataTypeHelper.macAdressConvertor(analyzer.getFrame().getDstMacAddress()));
                if (Arrays.equals(ali.getDstMacAddress(), analyzer.getFrame().getDstMacAddress()) || ali.getDstMacAddress() == null) {
                    logger.debug("------------------------------> B");
                    if (analyzer.getFrame().getIsIpv4()) {
                        logger.debug("------------------------------> C");
                        if (Arrays.equals(analyzer.getFrame().getIpv4parser().getSourceIPbyte(), ali.getSrcIpAddress()) || ali.getSrcIpAddress() == null) {
                            logger.debug("------------------------------> D");
                            if (Arrays.equals(analyzer.getFrame().getIpv4parser().getDestinationIPbyte(), ali.getDstIpAddress()) || ali.getDstIpAddress() == null) {
                                logger.debug("------------------------------> E");
                                logger.debug("isICMP -> " + analyzer.getFrame().getIpv4parser().getIsIcmp() + " ali.IPv4 -> " + ali.getIpv4Protocol());
                                if (ali.getIpv4Protocol() == null || (analyzer.getFrame().getIpv4parser().getIsIcmp() && ali.getIpv4Protocol().equals(1))) {
                                    logger.debug("------------------------------> F");
                                    ali.countFilterBlockage();
                                    logger.debug("stav ali.getAction " + ali.getAction());
                                    if (!ali.getAction()) {
                                        logger.debug("packet DENY filtrom OK -> zhoda");
                                    } else {
                                        logger.debug("packet ALLOW filtrom OK -> zhoda");
                                    }
                                    return ali.getAction();
                                } else if (analyzer.getFrame().getIpv4parser().isIsTcp() && ali.getIpv4Protocol().equals(6)) {
                                    logger.debug("------------------------------> G");
                                    if (analyzer.getFrame().getIpv4parser().getTcpParser().getSourcePort().equals(ali.getSrcPort()) || ali.getSrcPort() == null) {
                                        if (analyzer.getFrame().getIpv4parser().getTcpParser().getDestinationPort().equals(ali.getDstPort()) || ali.getDstPort() == null) {
                                            if (!ali.getAction()) {
                                                logger.debug("packet DENY filtrom OK -> zhoda");
                                            } else {
                                                logger.debug("packet ALLOW filtrom OK -> zhoda");
                                            }
                                            ali.countFilterBlockage();
                                            return ali.getAction();
                                        }
                                    }
                                } else if (analyzer.getFrame().getIpv4parser().isIsUdp() && ali.getIpv4Protocol().equals(17)) {
                                    logger.debug("------------------------------> H");
                                    if (DataHelpers.toInt(analyzer.getFrame().getIpv4parser().getUdpParser().getSourcePort()).equals(ali.getSrcPort()) || ali.getSrcPort() == null) {
                                        if (DataHelpers.toInt(analyzer.getFrame().getIpv4parser().getUdpParser().getDestinationPort()).equals(ali.getDstPort()) || ali.getDstPort() == null) {
                                            if (!ali.getAction()) {
                                                logger.debug("packet DENY filtrom OK -> zhoda");
                                            } else {
                                                logger.debug("packet ALLOW filtrom OK -> zhoda");
                                            }
                                            ali.countFilterBlockage();
                                            return ali.getAction();
                                        }
                                    }
                                } else if (!analyzer.getFrame().getIpv4parser().isIsTcp() && !analyzer.getFrame().getIpv4parser().isIsUdp() && !analyzer.getFrame().getIpv4parser().getIsIcmp()) {
                                    logger.debug("------------------------------> I");
                                    return true;
                                }
                            }
                        }
                    } else {
                        logger.debug("------------------------------> J");
                        return true;
                    }
                }
            }
        }
        logger.debug("------------------------------> K");
        logger.debug("presiel NOT AFFECTED filtrom OK -> ziadna zhoda");
        return true;
    }

    public CopyOnWriteArrayList<AccesListItem> getAclIn() {
        return aclIn;
    }

    public CopyOnWriteArrayList<AccesListItem> getAclOut() {
        return aclOut;
    }

    public CopyOnWriteArrayList<AccesListItem> getAcl(String direction) {
        if (direction.equals("IN")) {
            return aclIn;
        } else {
            return aclOut;
        }
    }

}
