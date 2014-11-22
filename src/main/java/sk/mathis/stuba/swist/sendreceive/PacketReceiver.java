/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.sendreceive;

import java.util.Arrays;
import java.util.Queue;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.swist.equip.Interface;
import sk.mathis.stuba.swist.equip.MacTable;
import sk.mathis.stuba.swist.equip.Packet;
import sk.mathis.stuba.swist.equip.MacAddress;
import sk.mathis.stuba.swist.equip.Statistics;
import sk.mathis.stuba.swist.analysers.Analyser;
import sk.mathis.stuba.swist.acl.AcccessList;
import sk.mathis.stuba.swist.acl.AccesListItem;

/**
 *
 * @author Mathis
 */
public class PacketReceiver implements Runnable {

    private final PcapIf device;
    private final StringBuilder errbuf = new StringBuilder();
    private final Queue<Packet> buffer;
    private Statistics statistic;
    private Pcap pcap;
    private Integer macWritten = 0;
    private MacTable macTable;
    private Boolean run = true;
    private static Logger logger = LoggerFactory.getLogger(PacketReceiver.class);
    private Analyser analyzer;
    private AcccessList acl;

    public PacketReceiver(PcapIf device, Queue<Packet> buffer, MacTable macTable) {
        this.device = device;
        this.buffer = buffer;
        this.macTable = macTable;
        this.pcap = null;
        this.acl = new AcccessList();
        analyzer = new Analyser();
        statistic = new Statistics();

    }

    @Override
    public void run() {

        int snaplen = 64 * 1024;           // Capture all packets, no trucation  
        int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
        int timeout = 10 * 1000;           // 10 seconds in millis  
        pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
        PcapPacketHandler<String> jpacketHandler = new PcapPacketHandler<String>() {
            @Override
            public void nextPacket(PcapPacket packet, String user) {
                System.out.println("------------------------------> RX 1");
                macWritten = 0;

                if (packet != null) {
                    analyzer.analyzePacket(packet);
                    statistic.storeDataIn(analyzer.getPacketProtocols());

                    Packet pckt = null;
                    if (!acl.getAclIn().isEmpty()) {
                        System.out.println("------------------------------> RX 2");
                        if (!acl.checkAcl(packet, "IN")) {
                            pckt = new Packet(packet, device, pcap, "nOK");
                            System.out.println("packet na vstupe IN -> zablokovany");
                        } else {
                            pckt = new Packet(packet, device, pcap, "OK");
                            System.out.println("packet na vstupe IN -> povoleny");
                        }
                        if (acl.checkAcl(packet, "IN") == null) {

                        }
                    } else {
                        System.out.println("------------------------------> RX 3");
                        pckt = new Packet(packet, device, pcap, "OK");
                        System.out.println("packet na vstupe IN -> povoleny");
                    }

                    buffer.add(pckt);

                    for (Interface iface : macTable.getInterfaceList()) {
                        if (iface.getDevice().getName().equals(device.getName())) {

                            for (MacAddress array : iface.getSrcMacaddressList()) {
                                if (Arrays.equals(array.getSrcMacAddress(), packet.getByteArray(6, 6))) {
                                    //    System.out.println("uz je zapisana macadressa");
                                    array.setLastActiveTime();
                                    iface.setActive();
                                    macWritten = 1;
                                }
                            }
                            if (iface.getSrcMacaddressList().isEmpty() || macWritten.equals(0)) {
                                //              System.out.println("adding mac address" + DataTypeHelper.macAdressConvertor(packet.getByteArray(6, 6)));
                                iface.addMacAddress(packet.getByteArray(6, 6));
                            }
                        }
                    }
                }
            }

        };

        while (run) {
            //        System.out.println("bezi mi tu while");
            pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "");
        }
    }

    public void start() {
        this.run = true;
    }

    public void stop() {
        this.run = false;
    }

    public void startThread() {
        start();
        System.out.println("zapinam thread na " + device.getName());
        new Thread(this).start();
    }

    public void setPcap(Pcap pcap) {
        this.pcap = pcap;
    }

    public MacTable getMacTable() {
        return macTable;
    }

    public Pcap getPcap() {
        return pcap;
    }

    public AcccessList getAcl() {
        return acl;
    }

    public Statistics getStatistic() {
        return statistic;
    }

    public PcapIf getDevice() {
        return device;
    }

}
