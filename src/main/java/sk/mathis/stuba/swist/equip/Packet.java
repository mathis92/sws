/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.equip;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;

/**
 *
 * @author Mathis
 */
public class Packet {

    PcapPacket packet;
    PcapIf device;
    Pcap pcap;
    String action;
    Boolean isSpan = false;

    public Packet(PcapPacket packet, PcapIf device, Pcap pcap) {
        this.packet = packet;
        this.device = device;
        this.pcap = pcap;
    }

    public Packet(PcapPacket packet, PcapIf device, Pcap pcap, String action) {
        this.packet = packet;
        this.device = device;
        this.pcap = pcap;
        this.action = action;
    }

    public PcapIf getDevice() {
        return device;
    }
public void tagSpan(){
    isSpan = true;
}
    public Boolean IsSpan() {
        return isSpan;
    }

    public PcapPacket getPacket() {
        return packet;
    }

    public void setPacket(PcapPacket packet) {
        this.packet = packet;
    }
    
    public String getAction() {
        return action;
    }

    public Pcap getPcap() {
        return pcap;
    }

}
