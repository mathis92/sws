/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.equip;

import com.sun.prism.impl.PrismSettings;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.swist.sendreceive.PacketReceiver;
import sk.mathis.stuba.swist.sendreceive.PacketSender;

/**
 *
 * @author martinhudec
 */
public class Span implements Runnable {

    private final ArrayList<PcapIf> srcPort = new ArrayList<>();
    private final PcapIf dstPort;
    private Integer sniffCount = 0;
    private Boolean run = true;
    private Boolean strip = false;
    private final Queue<Packet> packetQueue;
    //private final PacketSender sender;
    private final org.slf4j.Logger logger = LoggerFactory.getLogger(Span.class);

    private PacketReceiver receiver;

    public Span(PcapIf srcPort, PcapIf dstPort, List<PcapIf> ethDevs, ArrayList<PacketReceiver> receiverList, MacTable macTable, String strip) {
        this.srcPort.add(srcPort);
        this.dstPort = dstPort;
        if(strip != null){
            this.strip = true;
        }

        this.packetQueue = new ConcurrentLinkedDeque<>();
        //  this.sender = new PacketSender(ethDevs, receiverList, macTable);
        for (PacketReceiver rcvr : receiverList) {
            if (rcvr.getDevice().getName().equals(dstPort.getName())) {
                receiver = rcvr;

            }
        }
    }

    public PcapIf getDstPort() {
        return dstPort;
    }

    public Boolean getStrip() {
        return strip;
    }

    public ArrayList<PcapIf> getSrcPort() {
        return srcPort;
    }

    public void incrementCount() {
        sniffCount++;
    }

    public Integer getSniffCount() {
        return sniffCount;
    }

    public void startSpan() {
        run = true;
    }

    public void stopSpan() {
        run = false;
    }

    public Queue<Packet> getPacketQueue() {
        return packetQueue;
    }

    @Override
    public void run() {
        byte[] packetByteArray;
        while (run) {
            try {
                while (!packetQueue.isEmpty()) {
                    Packet packet = packetQueue.poll();
                    packetByteArray = packet.getPacket().getByteArray(0, packet.getPacket().getCaptureHeader().caplen());
                    sniffCount++;
                    for (PcapIf sPort : srcPort) {
                        System.out.println("sniffujem packet z interfaceu " + sPort.getName() + " na inerface " + dstPort.getName());
                    }
                    if (receiver.getPcap().sendPacket(packetByteArray) != Pcap.OK) {
                        System.err.println(packet.getPcap().getErr());

                    }

                }

                Thread.sleep(1);
            } catch (InterruptedException ex) {
                Logger.getLogger(Span.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

}
