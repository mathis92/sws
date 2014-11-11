/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.analysers;

import org.jnetpcap.packet.PcapPacket;
import sk.mathis.stuba.swist.equip.DataTypeHelper;

/**
 *
 * @author Mathis
 */
public class TcpParser implements IAnalyser {

    private  byte[] sourcePortByte;
    private  byte[] destinationPortByte;
    private Integer sourcePort;
    private Integer destinationPort;
    private Integer DataOffset;
    private byte flags;
    private PcapPacket packet; 
    private Integer ihlSet;
    private boolean isTcp = false;

    public TcpParser(PcapPacket packet, Integer ihlSet) {
        this.packet = packet;
        this.ihlSet = ihlSet;

        analyse();
    }

  //  public TcpParser() {
    //  }
    @Override
    public void analyse() {
        isTcp = true;
        sourcePortByte = packet.getByteArray(34+ihlSet, 2);
        destinationPortByte = packet.getByteArray(36+ihlSet, 2);
        sourcePort = DataTypeHelper.toInt(sourcePortByte);
        destinationPort = DataTypeHelper.toInt(destinationPortByte);
        
    }

    public Integer getDataOffset() {
        return DataOffset;
    }

    public byte[] getDestinationPortByte() {
        return destinationPortByte;
    }

    public byte getFlags() {
        return flags;
    }

    public boolean getIsTcp() {
        return isTcp;
    }

    public Integer getDestinationPort() {
        return destinationPort;
    }

    public Integer getSourcePort() {
        return sourcePort;
    }

    public byte[] getSourcePortByte() {
        return sourcePortByte;
    }

}
