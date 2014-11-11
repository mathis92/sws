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
public class ArpParser implements IAnalyser {

    private String operationType;
    private  byte[] sourceIPbyte;
    private  byte[] destinationIPbyte;
    private  byte[] destinationMACbyte;
    private  byte[] sourceMACbyte;
    private final PcapPacket packet;
    
    public ArpParser(PcapPacket packet) {
        this.packet = packet;
        this.analyse();
    }

    @Override
    public void analyse() {
        byte[] opType = packet.getByteArray(14, 2);
        if (DataTypeHelper.toInt(opType) == 1) {
            operationType = "ARP-Request";
        } else if (DataTypeHelper.toInt(opType) == 2) {
            operationType = "ARP-Reply";
        }
    }

    public byte[] getDestinationIPbyte() {
        return destinationIPbyte;
    }

    public byte[] getDestinationMACbyte() {
        return destinationMACbyte;
    }

    public String getOperationType() {
        return operationType;
    }

    public byte[] getSourceIPbyte() {
        return sourceIPbyte;
    }

    public byte[] getSourceMACbyte() {
        return sourceMACbyte;
    }

    
    
    
}
