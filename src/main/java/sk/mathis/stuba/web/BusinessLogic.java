package sk.mathis.stuba.web;

import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import sk.mathis.stuba.swist.sendreceive.DeviceFinder;

public class BusinessLogic {

    private final List<String> portList = new ArrayList<>();
    private Logger logger = org.slf4j.LoggerFactory.getLogger(BusinessLogic.class);

    public void addPort(String name) {
        logger.debug("Pridavam port " + name);
        this.portList.add(name);
    }

    public List<String> getPortList() {
        return this.portList;
    }
}
