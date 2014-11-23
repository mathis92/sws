/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.sendreceive;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.zip.CRC32;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import sk.mathis.stuba.swist.equip.MacTable;
import sk.mathis.stuba.swist.equip.Packet;
import sk.mathis.stuba.swist.analysers.Analyser;

/**
 *
 * @author Mathis
 */
public class PacketForwarder implements Runnable {

    private final Queue<Packet> buffer;
    private final PacketSender sender;
    private final ArrayList<PacketReceiver> receiverList;
    private final MacTable macTable;
    private final SwitchManager manager;
    private final Analyser analyzer = new Analyser();

    public PacketForwarder(Queue<Packet> buffer, List<PcapIf> ethDevs, ArrayList<PacketReceiver> receiverList, MacTable macTable, SwitchManager manager) {
        this.buffer = buffer;
        this.macTable = macTable;
        this.manager = manager;
        this.receiverList = receiverList;
        this.sender = new PacketSender(ethDevs, receiverList, macTable, manager);
    }

    @Override
    public void run() {
        while (true) {
            while (!buffer.isEmpty()) {
                Packet pckt = buffer.poll();
                macTable.CheckCableChange(pckt);
                int i = 0;
                if (manager.getSpan() != null) {
                    analyzer.analyzePacket(pckt.getPacket());

                    if (manager.getSpan().getStrip()) {
                        if (analyzer.getFrame().isVlan) {
                            pckt.setPacket(stripVlanTag(pckt.getPacket()));
                            manager.getSpan().getPacketQueue().add(pckt);
                        } else {
                            manager.getSpan().getPacketQueue().add(pckt);
                        }
                    } else {
                        manager.getSpan().getPacketQueue().add(pckt);
                    }
                }
                if (pckt.getAction().equals("OK")) {

                    sender.sendPacket(pckt);

                }
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException ex) {
                Logger.getLogger(PacketForwarder.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public PcapPacket stripVlanTag(PcapPacket packet) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            PcapPacket pckt;
            byte[] macHeader = packet.getByteArray(0, 12);
            byte[] frame = packet.getByteArray(16, (packet.getCaptureHeader().caplen() - 16));
            baos.write(macHeader, 0, macHeader.length);
            baos.write(frame, 0, frame.length);

            CRC32 crc32 = new CRC32();
            crc32.update(macHeader, 0, macHeader.length);
            crc32.update(frame, 0, frame.length);
            int crc = (int) (crc32.getValue() & 0xffffffff);
            byte[] crcOrig = ByteBuffer.allocate(4).putInt(crc).array();
            byte[] crcPopici = new byte[crcOrig.length];
            for (int i = 0; i < crcOrig.length; i++) {
                crcPopici[crcPopici.length - 1 - i] = crcOrig[i];
            }
            baos.write(crcPopici);
            pckt = new PcapPacket(packet);
            pckt.setByteArray(0, baos.toByteArray());
            return pckt;
        } catch (IOException ex) {
            throw new RuntimeException(ex);
        }
    }

}
