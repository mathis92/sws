/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.sendreceive;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import sk.mathis.stuba.swist.equip.Interface;
import sk.mathis.stuba.swist.equip.MacTable;
import sk.mathis.stuba.swist.equip.Packet;
import sk.mathis.stuba.swist.equip.MacAddress;
import sk.mathis.stuba.swist.analysers.Analyser;

/**
 *
 * @author Mathis
 */
public class PacketSender {

    byte[] packetByteArray;
    List<PcapIf> ethDevs;
    ArrayList<PacketReceiver> receivedList;
    public MacTable macTable;
    private Analyser analyzer;
    private Integer sent = 0;

    public PacketSender(List<PcapIf> ethDevs, ArrayList<PacketReceiver> receivedList, MacTable macTable) {
        this.ethDevs = ethDevs;
        this.macTable = macTable;
        this.receivedList = receivedList;
        analyzer = new Analyser();

    }

    public void sendPacket(Packet packet) {
        sent = 0;
        // System.out.println(packet.getPacket().getCaptureHeader().caplen());
        this.packetByteArray = packet.getPacket().getByteArray(0, packet.getPacket().getCaptureHeader().caplen());

        for (Interface iface : macTable.getInterfaceList()) {
            for (MacAddress macaddress : iface.getSrcMacaddressList()) {
                if (Arrays.equals(macaddress.getSrcMacAddress(), packet.getPacket().getByteArray(0, 6))) {
//                    System.out.println("Nasiel som cielovu mac adresu");

                    for (PacketReceiver rcvr : receivedList) {
                        //                      System.out.println(pack.getDevice().getName() + " nazov zariadenia z received " + iface.getDevice().getName() + " nazov z interfaceu");
                        if (iface.getDevice().getName().equals(rcvr.getDevice().getName())) {
                            //                        System.out.println("posielam na " + pack.getDevice().getName());
                            sent = 1;
                            if (rcvr.getPcap() != null) {
                                analyzer.analyzePacket(packet.getPacket());
                                rcvr.getStatistic().storeDataOut(analyzer.getPacketProtocols());
                                System.out.println("packetla na vystupe po prechode checkACL"  +rcvr.getAcl().checkAcl(packet.getPacket(), "OUT"));

                                if (rcvr.getAcl().checkAcl(packet.getPacket(), "OUT")) {
                                    System.out.println("packet presiel filtrom OUT");
                                    if (rcvr.getPcap().sendPacket(packetByteArray) != Pcap.OK) {
                                        System.err.println(packet.getPcap().getErr());
                                    }

                                } else {
                                         System.out.println("Packet nepresiel filtrom OUT bol zablokovany");
                                     }

                                }
                            }

                        }
                    }
                }
            }
            if (sent.equals(0)) {
                //      System.out.println("\n som v broadcaste \n");
                for (PacketReceiver pack : receivedList) {
                    if (pack.getPcap() != null) {
                        if (!pack.getDevice().getName().equals(packet.getDevice().getName())) {
                            if (pack.getPcap().sendPacket(packetByteArray) != Pcap.OK) {
                                System.err.println(pack.getPcap().getErr());
                            }
                        }
                    }
                }

            }
        }
    }
