/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.equip;

import java.util.ArrayList;
import java.util.concurrent.CopyOnWriteArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sk.mathis.stuba.swist.analysers.ProtocolList;

/**
 *
 * @author martinhudec
 */
public class Statistics {

    private final CopyOnWriteArrayList<ProtocolItem> protocolListIn;
    private final CopyOnWriteArrayList<ProtocolItem> protocolListOut;
    private Integer stored = 0;
    private Logger logger = LoggerFactory.getLogger(Statistics.class);

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

    public void storeDataIn(ProtocolList packetProtocols) {

        for (ProtocolItem item : packetProtocols.getProtoList()) {
            if (item.getProtocol() != null) {
                stored = 0;
                if (protocolListIn.isEmpty()) {
                    switch (item.getProtocol()) {
                        case "TCP":
                            item.getTcpPort().add(packetProtocols.getPort());
                            item.getTcpPortCount().add(1);
                            break;
                        case "UDP":
                            item.getUdpPort().add(packetProtocols.getPort());
                            item.getUdpPortCount().add(1);
                            break;
                        case "other":
                            item.incrOther();
                            break;
                    }
                    protocolListIn.add(item);
                } else {
                    for (ProtocolItem protocol : protocolListIn) {

                        if (protocol.getProtocol().equals(item.getProtocol())) {
                            protocol.countUp();
                            switch (item.getProtocol()) {
                                case "TCP":
                                    int i = 0;
                                    int found = 0;
                                    if (protocol.getTcpPort().isEmpty()) {
                                        protocol.getTcpPort().add(packetProtocols.getPort());
                                        protocol.getTcpPortCount().add(1);
                                    } else {
                                        for (String port : protocol.getTcpPort()) {
                                            if (packetProtocols.getPort() != null && port != null) {
                                                if (port.equals(packetProtocols.getPort())) {
                                                    protocol.getTcpPortCount().
                                                            set(i,
                                                                    protocol.getTcpPortCount().
                                                                    get(i) + 1);
                                                    // logger.debug("PRIDAVAM DO UDP PORT COUNT LISTU ++");
                                                    found = 1;
                                                }
                                                i++;
                                            }
                                        }
                                        if (found == 0) {
                                            protocol.getTcpPort().add(packetProtocols.getPort());
                                            protocol.getTcpPortCount().add(1);
                                        }
                                    }
                                    break;
                                case "UDP":
                                    i = 0;
                                    found = 0;
                                    if (protocol.getUdpPort().isEmpty()) {
                                        protocol.getUdpPort().add(packetProtocols.getPort());
                                        protocol.getUdpPortCount().add(1);
                                    } else {

                                        for (String port : protocol.getUdpPort()) {
                                            if (packetProtocols.getPort() != null && port != null) {
                                                if (port.equals(packetProtocols.getPort())) {
                                                    protocol.getUdpPortCount().
                                                            set(i,
                                                                    protocol.getUdpPortCount().
                                                                    get(i) + 1);
                                                    // logger.debug("PRIDAVAM DO UDP PORT COUNT LISTU ++");
                                                    found = 1;
                                                }
                                            }
                                            i++;

                                        }
                                        if (found == 0) {
                                            
                                            protocol.getUdpPort().add(packetProtocols.getPort());
                                            protocol.getUdpPortCount().add(1);
                                        }
                                    }
                                    break;
                                case "other": {
                                    item.incrOther();
                                }
                                break;
                            }
                            logger.debug("protocol: " + protocol.getProtocol() + " vrstva: " + protocol.getLayer() + " pocet: " + protocol.getCount());
                            stored = 1;
                            break;
                        }
                    }
                    if (stored.equals(0)) {
                        switch (item.getProtocol()) {
                            case "TCP":
                                item.getTcpPort().add(packetProtocols.getPort());
                                item.getTcpPortCount().add(1);
                                break;
                            case "UDP":
                                item.getUdpPort().add(packetProtocols.getPort());
                                item.getUdpPortCount().add(1);
                                break;
                            case "other":
                                item.incrOther();
                                break;
                        }
                        protocolListIn.add(item);
                        logger.debug("protocol: " + item.getProtocol() + " vrstva: " + item.getLayer() + " pocet: " + item.getCount());
                    }
                }
            }
        }
    }

    public void storeDataOut(ProtocolList packetProtocols) {

        for (ProtocolItem item : packetProtocols.getProtoList()) {
            if (item.getProtocol() != null) {
                stored = 0;
                if (protocolListOut.isEmpty()) {
                    switch (item.getProtocol()) {
                        case "TCP":
                            item.getTcpPort().add(packetProtocols.getPort());
                            item.getTcpPortCount().add(1);
                            break;
                        case "UDP":
                            item.getUdpPort().add(packetProtocols.getPort());
                            item.getUdpPortCount().add(1);
                            break;
                        case "other":
                            item.incrOther();
                            break;
                    }
                    protocolListOut.add(item);
                } else {
                    for (ProtocolItem protocol : protocolListOut) {

                        if (protocol.getProtocol().equals(item.getProtocol())) {
                            protocol.countUp();
                            switch (item.getProtocol()) {
                                case "TCP":
                                    int i = 0;
                                    int found = 0;
                                    if (protocol.getTcpPort().isEmpty()) {
                                        protocol.getTcpPort().add(packetProtocols.getPort());
                                        protocol.getTcpPortCount().add(1);
                                    } else {
                                        for (String port : protocol.getTcpPort()) {
                                            if (port.equals(packetProtocols.getPort())) {
                                                protocol.getTcpPortCount().
                                                        set(i,
                                                                protocol.getTcpPortCount().
                                                                get(i) + 1);
                                                // logger.debug("PRIDAVAM DO UDP PORT COUNT LISTU ++");
                                                found = 1;
                                            }
                                            i++;
                                        }
                                        if (found == 0) {
                                            protocol.getTcpPort().add(packetProtocols.getPort());
                                            protocol.getTcpPortCount().add(1);
                                        }
                                    }
                                    break;
                                case "UDP":
                                    i = 0;
                                    found = 0;
                                    if (protocol.getUdpPort().isEmpty()) {
                                        protocol.getUdpPort().add(packetProtocols.getPort());
                                        protocol.getUdpPortCount().add(1);
                                    } else {
                                        for (String port : protocol.getUdpPort()) {
                                            if (port.equals(packetProtocols.getPort())) {
                                                protocol.getUdpPortCount().
                                                        set(i,
                                                                protocol.getUdpPortCount().
                                                                get(i) + 1);
                                                // logger.debug("PRIDAVAM DO UDP PORT COUNT LISTU ++");
                                                found = 1;
                                            }
                                            i++;
                                        }
                                        if (found == 0) {
                                            protocol.getUdpPort().add(packetProtocols.getPort());
                                            protocol.getUdpPortCount().add(1);
                                        }
                                    }
                                    break;
                                case "other":
                                    item.incrOther();
                                    break;
                            }
                            logger.debug("protocol: " + protocol.getProtocol() + " vrstva: " + protocol.getLayer() + " pocet: " + protocol.getCount());
                            stored = 1;
                            break;
                        }
                    }
                    if (stored.equals(0)) {
                        switch (item.getProtocol()) {
                            case "TCP":
                                item.getTcpPort().add(packetProtocols.getPort());
                                item.getTcpPortCount().add(1);
                                break;
                            case "UDP":
                                item.getUdpPort().add(packetProtocols.getPort());
                                item.getUdpPortCount().add(1);
                                break;
                            case "other":
                                item.incrOther();
                                break;
                        }
                        protocolListOut.add(item);
                        logger.debug("protocol: " + item.getProtocol() + " vrstva: " + item.getLayer() + " pocet: " + item.getCount());
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
