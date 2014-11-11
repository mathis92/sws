/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.analysers;

import org.jnetpcap.packet.PcapPacket;

/**
 *
 * @author Mathis
 */
public class UdpParser implements IAnalyser {

    private byte[] sourcePort;
    private byte[] destinationPort;
    private boolean isUdp = false;
    private PcapPacket packet;
    private Integer ihlSet;

    public UdpParser(PcapPacket packet, Integer ihlSet) {
        this.ihlSet = ihlSet;
        this.packet = packet;
        analyse();
    }

    //  public TcpParser() {
    //  }
    @Override
    public void analyse() {
        isUdp = true;
        sourcePort = packet.getByteArray(34 + ihlSet, 2);
        destinationPort = packet.getByteArray(36 + ihlSet, 2);
    }

    public byte[] getDestinationPort() {
        return destinationPort;
    }

    public boolean isIsUdp() {
        return isUdp;
    }

    public byte[] getSourcePort() {
        return sourcePort;
    }

}
