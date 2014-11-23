/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sk.mathis.stuba.swist.sendreceive;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.log4j.spi.LoggerFactory;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.slf4j.Logger;

/**
 *
 * @author Mathis
 */
public final class DeviceFinder {

    public List<PcapIf> ethDevs = new ArrayList<>(); // Will be filled with NICs  
    private Logger logger = org.slf4j.LoggerFactory.getLogger(DeviceFinder.class);

    public DeviceFinder() throws IOException {
        findDevices();
    }

    public void findDevices() throws IOException {
        List<PcapIf> alldevs = new ArrayList<>();
        StringBuilder errbuf = new StringBuilder(); // For any error msgs  
        int r = Pcap.findAllDevs(alldevs, errbuf);
        if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
            System.err.printf("Can't read list of devices, error is %s", errbuf
                    .toString());
            return;
        }
        for (PcapIf dev : alldevs) {
            if (dev.getName().startsWith("eth")) {
                if (!dev.getName().equals("eth0")) {
                    ethDevs.add(dev);
                }
            }
        }
        logger.debug("Network devices found:");

        int i = 0;
        for (PcapIf device : ethDevs) {
            String description
                    = (device.getDescription() != null) ? device.getDescription()
                    : "No description available";
            System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
        }

    }

    public List<PcapIf> getEthDevs() {
        return ethDevs;
    }

}
