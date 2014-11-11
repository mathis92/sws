package sk.mathis.stuba.web;

import java.util.ArrayList;
import java.util.List;

public class BusinessLogic {

    private final List<String> portList = new ArrayList<>();

    public void addPort(String name) {
        System.out.println("Pridavam port " + name);
        this.portList.add(name);
    }

    public List<String> getPortList() {
        return this.portList;
    }
}
