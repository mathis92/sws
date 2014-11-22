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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private Logger logger;

    public PacketSender(List<PcapIf> ethDevs, ArrayList<PacketReceiver> receivedList, MacTable macTable) {
        this.ethDevs = ethDevs;
        this.macTable = macTable;
        this.receivedList = receivedList;
        analyzer = new Analyser();
        this.logger = LoggerFactory.getLogger(PacketSender.class);
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
                            logger.debug("SENDING PACKET FROM " + iface.getDevice().getName() + " TO " + packet.getDevice().getName());
                            //                        System.out.println("posielam na " + pack.getDevice().getName());
                            sent = 1;
                            if (rcvr.getPcap() != null) {
                                analyzer.analyzePacket(packet.getPacket());
                                rcvr.getStatistic().storeDataOut(analyzer.getPacketProtocols());
                                //System.out.println("packetla na vystupe  OUT - > "  +rcvr.getAcl().checkAcl(packet.getPacket(), "OUT"));

                                if (rcvr.getAcl().checkAcl(packet.getPacket(), "OUT")) {
                                    logger.debug("ALLOWED packet na vystupe OUT");
                                    if (rcvr.getPcap().sendPacket(packetByteArray) != Pcap.OK) {
                                        System.err.println(packet.getPcap().getErr());
                                    }

                                } else {
                                    logger.debug("BLOCKED Packet na vystupe OUT");
                                }

                            }
                        }

                    }
                }
            }
        }
        if (sent.equals(0)) {
            //      System.out.println("\n som v broadcaste \n");
            logger.debug("BROADCAST");
            for (PacketReceiver receiver : receivedList) {
                if (receiver.getPcap() != null) {
                    logger.debug("receiver.deviceName " + receiver.getDevice().getName() + " ||| " + " packet.deviceName" + packet.getDevice().getName());
                    if (!receiver.getDevice().getName().equals(packet.getDevice().getName())) {
                        logger.debug("receiver.deviceName " + receiver.getDevice().getName() + " ||| " + " packet.deviceName" + packet.getDevice().getName());
                        if (receiver.getPcap().sendPacket(packetByteArray) != Pcap.OK) {
                            System.err.println(receiver.getPcap().getErr());
                        }
                    }
                }
            }

        }
    }
}
