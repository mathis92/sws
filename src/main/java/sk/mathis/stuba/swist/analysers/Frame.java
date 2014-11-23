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
public final class Frame {



    private String frameType;
    public byte[] etherType;
    private byte[] srcMacAddress;
    private byte[] dstMacAddress;
    private boolean isIpV4 = false;
    private boolean isARP = false;
    public IpV4Parser ipv4;
    public ArpParser arp;
    public PcapPacket packet;
    public Integer communicationListId;
    public Integer comId;
    public String protocol;
    public String applicationProtocol;
    public boolean isVlan = false;

    public Frame(PcapPacket packet) {
        this.packet = packet;
        this.findEtherType();
        this.gatherMacAdress();
    }

    public void findEtherType() {
        Integer etherTypeInt;
        etherType = packet.getByteArray(12,2);
        
        etherTypeInt = DataTypeHelper.toInt(etherType);
        if (etherTypeInt >= 1536) {
            frameType = "Ethernet II";
            if (etherTypeInt == 2048) {
                isIpV4 = true;
                ipv4 = new IpV4Parser(packet);
                ipv4.analyse();
            }
            else if (etherTypeInt == 2054) {
                isARP = true;
                arp = new ArpParser(packet);
                arp.analyse();
            }else if (etherTypeInt == 33024){
                isVlan = true;
            }

        }
        if (etherTypeInt <= 1500) {
            byte temp = packet.getByte(14);
            if ((temp & 0xff) == 0xFF) {
                byte temp2 = packet.getByte(15);
                if ((temp2 & 0xff) == 0xFF) {
                    frameType = "Novell raw IEEE 802.3";
                }
            } else if ((temp & 0xff) == 0xAA) {
                    byte temp2 = packet.getByte(15);
                if ((temp2 & 0xff) == 0xAA) {
                    frameType = "IEEE 802.2 SNAP";
                }
            } else {
                frameType = "IEEE 802.2 LLC";
            }
        }
        
        
    }
    
      public void gatherMacAdress() {
          srcMacAddress = packet.getByteArray(6, 6);
          dstMacAddress = packet.getByteArray(0, 6);
    }

    public boolean getIsArp() {
        return isARP;
    }

    public PcapPacket getPacket() {
        return packet;
    }

    
    public String getProtocol() {
        return protocol;
    }

    public void setApplicationProtocol(String applicationProtocol) {
        this.applicationProtocol = applicationProtocol;
    }

    public String getApplicationProtocol() {
        return applicationProtocol;
    }
    
        public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public Integer getComId() {
        return comId;
    }

    public void setComId(Integer comId) {
        this.comId = comId;
    }

    public void setCommunicationId(Integer communicationId) {
        this.communicationListId = communicationId;
    }

    public Integer getCommunicationId() {
        return communicationListId;
    }

    public ArpParser getArpParser() {
        return arp;
    }

    public boolean getIsIpv4() {
        return isIpV4;
    }

    public IpV4Parser getIpv4parser() {
        return ipv4;
    }

    public byte[] getDstMacAddress() {
        return dstMacAddress;
    }

    public byte[] getSrcMacAddress() {
        return srcMacAddress;
    }


    public String getFrameType() {
        return frameType;
    }


}
