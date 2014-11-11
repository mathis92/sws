/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.equip;

import java.util.ArrayList;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 *
 * @author martinhudec
 */
public class Statistics {

    private final CopyOnWriteArrayList<ProtocolItem> protocolListIn;
    private final CopyOnWriteArrayList<ProtocolItem> protocolListOut;
    private Integer stored = 0;

    public Statistics() {
        protocolListIn = new CopyOnWriteArrayList<>();
        protocolListOut = new CopyOnWriteArrayList<>();
    }

    public void flushStatistics(String direction) {
        switch (direction) {
            case "IN":
                protocolListIn.clear();
                break;
            case "OUT":
                protocolListOut.clear();
                break;
        }
    }

    public void storeDataOut(ArrayList<ProtocolItem> packetProtocols) {

        for (ProtocolItem item : packetProtocols) {
            if (item.getProtocol() != null) {
                stored = 0;
                if (protocolListOut.isEmpty()) {
                    protocolListOut.add(item);

                } else {
                    for (ProtocolItem protocol : protocolListOut) {
                        if (protocol.getProtocol().equals(item.getProtocol())) {
                            protocol.countUp();
                            System.out.println("protocol: " + protocol.getProtocol() + " vrstva: " + protocol.getLayer() + " pocet: " + protocol.getCount());
                            stored = 1;
                            break;
                        }
                    }
                    if (stored.equals(0)) {
                        protocolListOut.add(item);
                        System.out.println("protocol: " + item.getProtocol() + " vrstva: " + item.getLayer() + " pocet: " + item.getCount());
                    }
                }
            }
        }
    }

    public void storeDataIn(ArrayList<ProtocolItem> packetProtocols) {
        for (ProtocolItem item : packetProtocols) {
            if (item.getProtocol() != null) {
                stored = 0;
                if (protocolListIn.isEmpty()) {
                    protocolListIn.add(item);
                } else {
                    for (ProtocolItem protocol : protocolListIn) {

                        if (protocol.getProtocol().equals(item.getProtocol())) {
                            protocol.countUp();
                            System.out.println("protocol: " + protocol.getProtocol() + " vrstva: " + protocol.getLayer() + " pocet: " + protocol.getCount());
                            stored = 1;
                            break;
                        }
                    }
                    if (stored.equals(0)) {
                        protocolListIn.add(item);
                        System.out.println("protocol: " + item.getProtocol() + " vrstva: " + item.getLayer() + " pocet: " + item.getCount());
                    }
                }
            }
        }
    }

    public CopyOnWriteArrayList<ProtocolItem> getProtocolListIn() {
        return protocolListIn;
    }

    public CopyOnWriteArrayList<ProtocolItem> getProtocolListOut() {
        return protocolListOut;
    }

}
