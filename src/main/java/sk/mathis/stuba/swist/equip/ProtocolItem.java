/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.equip;

/**
 *
 * @author martinhudec
 */
public class ProtocolItem {

    private Integer layer;
    private String protocol;
    private Integer count = 0;

    public ProtocolItem(String protocol, Integer layer) {
        this.protocol = protocol;
        this.layer = layer;
        this.count++;
    }

      
    public void countUp() {
        count++;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public void setLayer(Integer layer) {
        this.layer = layer;
    }

    public String getProtocol() {
        return protocol;
    }

    public Integer getCount() {
        return count;
    }

    public Integer getLayer() {
        return layer;
    }
}
