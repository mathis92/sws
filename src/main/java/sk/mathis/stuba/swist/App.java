package sk.mathis.stuba.swist;

import java.io.IOException;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.jnetpcap.packet.PcapPacket;
import sk.mathis.stuba.swist.sendreceive.PacketSender;
import sk.mathis.stuba.swist.sendreceive.SwitchManager;
import sk.mathis.stuba.web.MainServlet;
import sk.mathis.stuba.web.ResourceServlet;

public class App {

    public static PacketSender sender;
    public static PcapPacket packet;
    public static SwitchManager manager;

    public static void main(String[] argv) throws IOException, Exception {
        manager = new SwitchManager();

        Server webserver = new Server(8199);
        ServletContextHandler sch = new ServletContextHandler();
        sch.addServlet(new ServletHolder(new MainServlet(manager)), "/*");
        sch.addServlet(new ServletHolder(new ResourceServlet()), "/resource/*");
        webserver.setHandler(sch);
        webserver.start();
        webserver.join();

    }
}