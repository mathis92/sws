/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.analysers;

import java.io.IOException;
import java.io.FileNotFoundException;
import java.util.ArrayList;
import org.jnetpcap.packet.PcapPacket;
import sk.mathis.stuba.swist.equip.DataTypeHelper;
import sk.mathis.stuba.swist.equip.ProtocolItem;
import sk.mathis.stuba.swist.analysers.ProtocolList;
public class Analyser {

    private Frame frame;

    public ProtocolList getPacketProtocols() {
        ArrayList<ProtocolItem> protocolList = new ArrayList<>();
        String port = null;
                
        if (frame.getFrameType().equals("Ethernet II")) {
            protocolList.add(new ProtocolItem("Ethernet II", 2));
            if (frame.getIsArp()) {
                protocolList.add(new ProtocolItem("ARP", 3));
            } else if (frame.getIsIpv4()) {
                protocolList.add(new ProtocolItem("Ipv4", 3));
                if (frame.getIpv4parser().isIsTcp()) {
                    protocolList.add(new ProtocolItem("TCP", 4));
                    port = frame.getApplicationProtocol();
                } else if (frame.getIpv4parser().isIsUdp()) {
                    protocolList.add(new ProtocolItem("UDP", 4));
                    port = frame.getApplicationProtocol();
                } else if (frame.getIpv4parser().getIsIcmp()) {
                    protocolList.add(new ProtocolItem("ICMP", 4));
                }
            }
        } else {
            protocolList.add(new ProtocolItem(frame.getFrameType(), 2));
        }
        return new ProtocolList(protocolList, port);
    }

    public void analyzePacket(PcapPacket packet) {

        frame = new Frame(packet);

        if (frame.getIsIpv4()) {

            if (frame.getIpv4parser().getTcpParser() != null) {

                if (frame.getIpv4parser().getTcpParser().getIsTcp()) {
                    frame.setProtocol("TCP");

                    String tcpPort = DataTypeHelper.tcpMap.get(frame.getIpv4parser().getTcpParser().getDestinationPort());
                    if (tcpPort == null) {
                        tcpPort = DataTypeHelper.tcpMap.get(frame.getIpv4parser().getTcpParser().getSourcePort());

                    }
                    if (tcpPort != null) {
                        if (tcpPort.equals("www")) {
                            tcpPort = "http";
                        }

                        frame.setApplicationProtocol(tcpPort);
                    }
                }
            }
            if (frame.getIpv4parser().getUdpParser() != null) {
                if (frame.getIpv4parser().getUdpParser().isIsUdp()) {
                    frame.setProtocol("UDP");
                    String udpPort = DataTypeHelper.udpMap.get(DataTypeHelper.toInt(frame.getIpv4parser().getUdpParser().getDestinationPort()));
                    if (udpPort == null) {
                        udpPort = DataTypeHelper.udpMap.get(DataTypeHelper.toInt(frame.getIpv4parser().getUdpParser().getSourcePort()));
                    }

                    if (udpPort != null) {
                        if (udpPort.equals("www")) {
                            udpPort = "http";
                        }
                        frame.setApplicationProtocol(udpPort);
                    }
                }
            }

        }
    }

    public Frame getFrame() {
        return frame;
    }
}
