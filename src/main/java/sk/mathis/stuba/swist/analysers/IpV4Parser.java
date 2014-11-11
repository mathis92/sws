/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.analysers;

import java.util.ArrayList;
import org.jnetpcap.packet.PcapPacket;
import sk.mathis.stuba.swist.equip.DataTypeHelper;
 
/**
 *
 * @author Mathis
 */
public class IpV4Parser implements IAnalyser {

    private  byte[] sourceIPbyte;
    private String sourceIP;
    private String destinationIP;
    private  byte[] destinationIPbyte;
    private Integer ipV4length;
    private Integer ipV4theMostSentBytes = 0;
    private Integer ihl;
    private IcmpParser icmpParser;
    private byte ipv4Protocol;
    private String ipv4ProtocolName;
    private boolean isIcmp;
    private boolean isTcp;
    private boolean isUdp;
    private UdpParser udpParser = null;
    private TcpParser tcpParser = null;
    private Integer ihlSet = 0;
    private PcapPacket packet;

    public IpV4Parser(PcapPacket packet) {
        this.packet = packet;
        
    }

    @Override
    public void analyse() {
        ihl = DataTypeHelper.getIhl(packet.getByte(14));

        
       // byte[] ipv4Length;
       // ipv4Length = packet.getByteArray(16, 2);
       // ipV4length = DataTypeHelper.toInt(ipv4Length);

        if (ihl > 5) {
  //          ipV4length = ihl * 4;
        }
       // ipV4theMostSentBytes = ipV4length + 14;
        ipv4Protocol = packet.getByte(23);
        ipv4ProtocolName = DataTypeHelper.portMap.get(DataTypeHelper.singleToInt(ipv4Protocol));
        sourceIPbyte = packet.getByteArray(26, 4);
        destinationIPbyte = packet.getByteArray(30, 4);

        if (ihl > 5) {
            ihlSet = 4;
        }else { 
            ihlSet = 0;
        }
        
        if (ipv4ProtocolName.equalsIgnoreCase("ICMP")) {
            isIcmp = true; 
            icmpParser = new IcmpParser(packet,ihlSet);
        } 
        else if (ipv4ProtocolName.equalsIgnoreCase("TCP")) {
            isTcp = true;

            tcpParser = new TcpParser(packet,ihlSet);
        } 
        else if (ipv4ProtocolName.equalsIgnoreCase("UDP")) {
            isUdp = true;
            udpParser = new UdpParser(packet,ihlSet);
        } else {
            if(DataTypeHelper.otherPorts.contains(ipv4ProtocolName) == false){
            DataTypeHelper.otherPorts.add(ipv4ProtocolName);
            }
        }
    }

    public boolean getIsIcmp() {
        return isIcmp;
    }

    public TcpParser getTcpParser() {
        return tcpParser;
    }

     public UdpParser getUdpParser() {
        return udpParser;
    }

    public boolean isIsUdp() {
        return isUdp;
    }

    public boolean isIsTcp() {
        return isTcp;
    }

    public Integer getiPv4length() {
        return ipV4length;
    }

    public void setIpV4TheMostSentBytes(Integer ipV4) {
        this.ipV4theMostSentBytes = ipV4;
    }

    public Integer getIpV4theMostSentBytes() {
        return ipV4theMostSentBytes;
    }

    public byte[] getSourceIPbyte() {
        return sourceIPbyte;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public byte[] getDestinationIPbyte() {
        return destinationIPbyte;
    }

    public String getDestinationIP() {
        return destinationIP;
    }

    public IcmpParser getIcmpParser() {
        return icmpParser;
    }

}
