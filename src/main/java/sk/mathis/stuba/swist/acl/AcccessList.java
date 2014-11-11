/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.acl;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.concurrent.CopyOnWriteArrayList;
import org.jnetpcap.packet.PcapPacket;
import sk.mathis.stuba.swist.analysers.Analyser;
import sk.mathis.stuba.swist.equip.ProtocolItem;
import sk.mathis.stuba.swist.equip.DataHelpers;
import sk.mathis.stuba.swist.equip.DataTypeHelper;

/**
 *
 * @author martinhudec
 */
public class AcccessList {

    private ArrayList<AccesListItem> aclIn;
    private Analyser analyzer;
    private ArrayList<AccesListItem> aclOut;

    public AcccessList() {
        aclIn = new ArrayList<>();
        aclOut = new ArrayList<>();
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

    public void repairPriorities(ArrayList<AccesListItem> acl, Integer position) {
        for (int i = position + 1; i < acl.size(); i++) {
            acl.get(i).setPriority(acl.get(i).getPriority() - 1);
        }
    }

    public void deleteAclItem(Integer priority, String direction) {
        System.out.println(priority + " " + direction);
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
        Boolean passed = true;
        analyzer.analyzePacket(packet);
        ArrayList<ProtocolItem> packetProtocolList = analyzer.getPacketProtocols();
        for (AccesListItem ali : ((direction.equals("IN")) ? aclIn : aclOut)) {
            System.out.println(aclIn.size() + " velkost aclIn");
            if (Arrays.equals(ali.getSrcMacAddress(), analyzer.getFrame().getSrcMacAddress()) || ali.getSrcMacAddress() == null) {
                System.out.println("smer " + direction + " src mac adresa " + DataTypeHelper.macAdressConvertor(analyzer.getFrame().getSrcMacAddress()) + " dst mac addressa " + DataTypeHelper.macAdressConvertor(analyzer.getFrame().getDstMacAddress()));
                System.out.println("dostal som sa za mac src");
                if (Arrays.equals(ali.getDstMacAddress(), analyzer.getFrame().getDstMacAddress()) || ali.getDstMacAddress() == null) {
                    System.out.println("dostal som sa za mac dst");
                    if (analyzer.getFrame().getIsIpv4()) {
                        System.out.println("dostal som sa za ipv4");
                        if (Arrays.equals(analyzer.getFrame().getIpv4parser().getSourceIPbyte(), ali.getSrcIpAddress()) || ali.getSrcIpAddress() == null) {
                            System.out.println("dostal som sa za ip src");
                            if (Arrays.equals(analyzer.getFrame().getIpv4parser().getDestinationIPbyte(), ali.getDstIpAddress()) || ali.getDstIpAddress() == null) {
                                System.out.println("dostal som sa za ip dst");
                                if ((ali.getIpv4Protocol() == null) || (analyzer.getFrame().getIpv4parser().getIsIcmp() && ali.getIpv4Protocol().equals(1))) {
                                    passed = false;
                                    ali.countFilterBlockage();
                                    System.out.println("je to icmp zablokoval som je zo spravnej mac adresy");
                                    return passed;
                                } else if (analyzer.getFrame().getIpv4parser().isIsTcp() && ali.getIpv4Protocol().equals(6)) {
                                    System.out.println("dostal som sa za TCP");
                                    if (analyzer.getFrame().getIpv4parser().getTcpParser().getSourcePort().equals(ali.getSrcPort()) || ali.getSrcPort() == null) {
                                        System.out.println("dostal som sa za SRC port");
                                        if (analyzer.getFrame().getIpv4parser().getTcpParser().getDestinationPort().equals(ali.getDstPort()) || ali.getDstPort() == null) {
                                            System.out.println("dostal som sa za DST port a idem zablokovat tento packetla");
                                            passed = false;
                                            ali.countFilterBlockage();
                                            return passed;
                                        }
                                    }
                                } else if (analyzer.getFrame().getIpv4parser().isIsUdp() && ali.getIpv4Protocol().equals(17)) {
                                    if (DataHelpers.toInt(analyzer.getFrame().getIpv4parser().getUdpParser().getSourcePort()).equals(ali.getSrcPort()) || ali.getSrcPort() == null) {
                                        if (DataHelpers.toInt(analyzer.getFrame().getIpv4parser().getUdpParser().getDestinationPort()).equals(ali.getDstPort()) || ali.getDstPort() == null) {
                                            passed = false;
                                            ali.countFilterBlockage();
                                            return passed;
                                        }
                                    }
                                }
                            }
                        }
                    }

                }
            }

        }

        return passed;
    }

    public ArrayList<AccesListItem> getAclOut() {
        return aclOut;
    }

    public ArrayList<AccesListItem> getAcl(String direction) {
        if (direction.equals("IN")) {
            return aclIn;
        } else {
            return aclOut;
        }
    }

    public ArrayList<AccesListItem> getAclIn() {
        return aclIn;
    }

}
