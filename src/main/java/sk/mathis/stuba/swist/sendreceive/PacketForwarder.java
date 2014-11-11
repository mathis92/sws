/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.sendreceive;

import com.sun.javafx.scene.control.skin.VirtualFlow;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import sk.mathis.stuba.swist.equip.DataTypeHelper;
import sk.mathis.stuba.swist.equip.MacTable;
import sk.mathis.stuba.swist.equip.Packet;

/**
 *
 * @author Mathis
 */
public class PacketForwarder implements Runnable {

    private Queue<Packet> buffer;
    private PacketSender sender;
    private ArrayList<PacketReceiver> receiverList;
    private MacTable macTable;

    public PacketForwarder(Queue<Packet> buffer, List<PcapIf> ethDevs, ArrayList<PacketReceiver> receiverList, MacTable macTable) {
        this.buffer = buffer;
        this.macTable = macTable;
        this.receiverList = receiverList;
        this.sender = new PacketSender(ethDevs, receiverList, macTable);
    }

    @Override
    public void run() {
        while (true) {
            while (!buffer.isEmpty()) {
                Packet pckt = buffer.poll();
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

}
