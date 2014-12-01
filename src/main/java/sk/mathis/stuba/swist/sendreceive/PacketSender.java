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
import sk.mathis.stuba.swist.equip.DataTypeHelper;
import sk.mathis.stuba.swist.equip.Span;

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
    private SwitchManager manager;

    public PacketSender(List<PcapIf> ethDevs, ArrayList<PacketReceiver> receivedList, MacTable macTable, SwitchManager manager) {
        this.ethDevs = ethDevs;
        this.manager = manager;
        this.macTable = macTable;
        this.receivedList = receivedList;
        analyzer = new Analyser();
        this.logger = LoggerFactory.getLogger(PacketSender.class);
    }

    public void sendPacket(Packet packet) {
        sent = 0;
        // logger.debug(packet.getPacket().getCaptureHeader().caplen());
        this.packetByteArray = packet.getPacket().getByteArray(0, packet.getPacket().getCaptureHeader().caplen());
        int inter = 0;
        for (Interface iface : macTable.getInterfaceList()) {
           // logger.debug("\n interface cyklus " + inter + "\n");
            inter++;
            int macaddr = 0;
            for (MacAddress macaddress : iface.getSrcMacaddressList()) {
            //    logger.debug("\n macaddr cyklus " + macaddr + "\n");
                macaddr++;
                if (Arrays.equals(macaddress.getSrcMacAddress(), packet.getPacket().getByteArray(0, 6))) {
                    logger.debug("Nasiel som cielovu mac adresu " + DataTypeHelper.macAdressConvertor(macaddress.getSrcMacAddress()) + "posielam na port " + iface.getDevice().getName());
                    int rec = 0;
                    for (PacketReceiver rcvr : receivedList) {
             //           logger.debug("\n rcvr cyklus " + rec + "\n");
                        rec++;
                        logger.debug(packet.getDevice().getName() + " nazov zariadenia z received " + iface.getDevice().getName() + " nazov z interfaceu");
                        if (iface.getDevice().getName().equals(rcvr.getDevice().getName())) {
                            if (!iface.getDevice().getName().equals(packet.getDevice().getName())) {
                                logger.debug("SENDING PACKET FROM " + iface.getDevice().getName() + " TO " + packet.getDevice().getName());
                                sent = 1;
                                if (rcvr.getPcap() != null) {
                                    analyzer.analyzePacket(packet.getPacket());
                                    rcvr.getStatistic().storeDataOut(analyzer.getPacketProtocols());
                                    //logger.debug("packetla na vystupe  OUT - > "  +rcvr.getAcl().checkAcl(packet.getPacket(), "OUT"));

                                    if (rcvr.getAcl().checkAcl(packet.getPacket(), "OUT")) {
                                        if (rcvr.getPcap().sendPacket(packetByteArray) != Pcap.OK) {
                                            System.err.println(packet.getPcap().getErr());
                                        }
                                        break;

                                    } else {
          //                              logger.debug("BLOCKED Packet na vystupe OUT");
                                    }

                                }
                            }else { 
                                logger.debug("packet ide v ramci hubu");
                                sent = 1;
                            }
                        }

                    }
                }
            }
        }

        if (sent.equals(0)) {
            logger.debug("BROADCAST");
            for (PacketReceiver receiver : receivedList) {
                if (receiver.getPcap() != null) {
                    if (!receiver.getDevice().getName().equals(packet.getDevice().getName())) {
                           logger.debug("span " + manager.getSpan());
                        if (manager.getSpan() != null) {
                                logger.debug("receiver.deviceName " + receiver.getDevice().getName() + " ||| " + " packet.deviceName" + packet.getDevice().getName());

                            if (!manager.getSpan().getDstPort().getName().equals(receiver.getDevice().getName())) {
                                for (PcapIf srcPort : manager.getSpan().getSrcPort()) {
                                    if (!srcPort.getName().equals(packet.getDevice().getName())) {
                                        //   logger.debug("neposielam broatcast na span port " + manager.getSpan().getDstPort().getName());
          //                              logger.debug("receiver.deviceName " + receiver.getDevice().getName() + " ||| " + " packet.deviceName" + packet.getDevice().getName());
                                        if (receiver.getPcap().sendPacket(packetByteArray) != Pcap.OK) {
                                            System.err.println(receiver.getPcap().getErr());
                                        }
                                    }
                                }
                            }
                        } else {
                               logger.debug("receiver.deviceName " + receiver.getDevice().getName() + " ||| " + " packet.deviceName" + packet.getDevice().getName());
         //                   logger.debug("receiver.deviceName " + receiver.getDevice().getName() + " ||| " + " packet.deviceName" + packet.getDevice().getName());
                            
                            if (receiver.getPcap().sendPacket(packetByteArray) != Pcap.OK) {
                                System.err.println(receiver.getPcap().getErr());
                            }
                        }

                    } else { 
                        logger.debug("som v broatcaste a chcem posielat na rovnaky port ");
                    }
                }
            }

        }
    }

    public Boolean checkSpanPacket(String name) {
        for (PcapIf device : manager.getSpan().getSrcPort()) {
            logger.debug("Matching " + name + " -> " + device.getName());
            if (name.equals(device.getName())) {
                logger.debug("name " + name + " dev name " + device.getName() + "------------> true");
                return true;
            }
        }

        logger.debug("false");
        return false;
    }
}
