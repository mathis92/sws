/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.acl;

import sk.mathis.stuba.swist.equip.DataTypeHelper;

/**
 *
 * @author martinhudec
 */
public class AccesListItem {

    private byte[] srcMacAddress;
    private byte[] dstMacAddress;
    private byte[] srcIpAddress;
    private byte[] dstIpAddress;
    private Integer ipv4Protocol;
    private Integer srcPort;
    private Integer dstPort;
    private Integer priority;
    private Integer direction;
    private Integer blockCount = 0;

    public AccesListItem(Integer priority) {
    this.priority = priority;
    }

    
    public AccesListItem(byte[] srcMac, byte[] dstMac, byte[] srcIp, byte[] dstIp, Integer protocol, Integer port, Integer priority, Integer direction) {
        this.srcIpAddress = srcIp;
        this.srcMacAddress = srcMac;

        this.dstIpAddress = dstIp;
        this.dstMacAddress = dstMac;
        this.ipv4Protocol = protocol;
        this.srcPort = port;
        this.priority = priority;
        this.direction = direction;
       
    }

    public byte[] getDstIpAddress() {
        return dstIpAddress;
    }

    public byte[] getDstMacAddress() {
        return dstMacAddress;
    }

    public void countFilterBlockage(){
        blockCount++;
    }

    public Integer getBlockCount() {
        return blockCount;
    }
 
    public Integer getDstPort() {
        return dstPort;
    }

    public Integer getSrcPort() {
        return srcPort;
    }

    public void setDstPort(Integer dstPort) {
        this.dstPort = dstPort;
    }

    public void setSrcPort(Integer srcPort) {
        this.srcPort = srcPort;
    }

    
    public Integer getProtocol() {
        return ipv4Protocol;
    }

    public Integer getIpv4Protocol() {
        return ipv4Protocol;
    }

    public void setDirection(Integer direction) {
        this.direction = direction;
    }

    public void setIpv4Protocol(Integer ipv4Protocol) {
        this.ipv4Protocol = ipv4Protocol;
    }


    public byte[] getSrcIpAddress() {
        return srcIpAddress;
    }

    public byte[] getSrcMacAddress() {
        return srcMacAddress;
    }

    public void setDstIpAddress(byte[] dstIpAddress) {
        this.dstIpAddress = dstIpAddress;
    }

    public void setDstMacAddress(byte[] dstMacAddress) {
        this.dstMacAddress = dstMacAddress;
    }

    public void setProtocol(Integer protocol) {
        this.ipv4Protocol = protocol;
    }

    public void setSrcIpAddress(byte[] srcIpAddress) {
        this.srcIpAddress = srcIpAddress;
    }

    public void setSrcMacAddress(byte[] srcMacAddress) {
        this.srcMacAddress = srcMacAddress;
    }

    public void setPriority(Integer priority) {
        this.priority = priority;
    }

    public Integer getPriority() {
        return priority;
    }

    public Integer getDirection() {
        return direction;
    }

}
