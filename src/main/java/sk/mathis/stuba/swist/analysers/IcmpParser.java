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
public class IcmpParser implements IAnalyser {

    private byte type;
    private byte code; 
    private byte[] checksum;
    private String typeString;
    private PcapPacket packet;
    private Integer ihlSet;
    
    
    public IcmpParser(PcapPacket packet, Integer ihlSet) {
        this.ihlSet = ihlSet;
        this.packet = packet;
        this.analyse();
    }

    @Override
    public void analyse() {

       type = packet.getByte(34 + ihlSet);
       code = packet.getByte(35 + ihlSet);
      checksum = packet.getByteArray(36+ihlSet, 2);
    }

    public byte getType() {
        return type;
    }

    public byte getCode() {
        return code;
    }

    public byte[] getChecksum() {
        return checksum;
    } 
    
    
    
}
