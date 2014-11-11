package sk.mathis.stuba.web;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import sk.mathis.stuba.swist.acl.AccesListItem;
import sk.mathis.stuba.swist.equip.DataTypeHelper;
import sk.mathis.stuba.swist.equip.Interface;
import sk.mathis.stuba.swist.sendreceive.SwitchManager;
import sk.mathis.stuba.swist.equip.MacAddress;
import sk.mathis.stuba.swist.sendreceive.PacketReceiver;
import sk.mathis.stuba.swist.equip.ProtocolItem;

public class MainServlet extends HttpServlet {

    private final SwitchManager manager;
    private final List<WebMenuItem> wmiList = new ArrayList<>();
    private String currentPage;

    public MainServlet(SwitchManager manager) {
        this.manager = manager;
        this.wmiList.add(new WebMenuItem("Switch PSIP", "/index.html", "fullscreen"));
        this.wmiList.add(new WebMenuItem("Interfaces", "/interfaces.html", "resize-small"));
        this.wmiList.add(new WebMenuItem("Access lists (filters)", "/acl.html", "minus"));
        this.wmiList.add(new WebMenuItem("Mac Table", "/status.html", "cloud"));
        this.wmiList.add(new WebMenuItem("Statistics", "/statistics.html", "cloud"));
        this.wmiList.add(new WebMenuItem("Span", "/help.html", "question-sign"));
    }

    private String getMacAddresses(Interface interf) {
        String html = "";
        if (!interf.getSrcMacaddressList().isEmpty()) {
            for (MacAddress addr : interf.getSrcMacaddressList()) {
                html += DataTypeHelper.macAdressConvertor(addr.getSrcMacAddress());

                if (interf.getSrcMacaddressList().size() > 1) {
                    html += "<br>";
                }
            }
        }
        return html;
    }

    private String getInterfaceState(Interface interf) {
        String state = "";
        switch (interf.getState()) {
            case 0:
                state = "Disabled";
                break;
            case 1:
                state = "Active";
                break;

        }
        return state;
    }

    private void changeInterfaceState(String interfaceName) {
        for (Interface interf : this.manager.getMacTable().getInterfaceList()) {
            if (interf.getDevice().getName().equals(interfaceName)) {
                switch (interf.getState()) {
                    case 0:

                        interf.setActive();
                        this.manager.startReceiverThread(interfaceName);
                        ;
                        break;
                    case 1:
                        interf.setDisabled();
                        this.manager.interruptReceiverThread(interfaceName);
                        ;

                        break;
                }

            }
        }
    }

    private String getLastActiveTime(Interface interf) {
        String time = "";
        if (!interf.getSrcMacaddressList().isEmpty()) {
            for (MacAddress addr : interf.getSrcMacaddressList()) {
                time += (addr.getLastActiveTime() < 2) ? "active" : Long.toString(addr.getLastActiveTime()) + " seconds";

                if (interf.getSrcMacaddressList().size() > 1) {
                    time += "<br>";
                }
            }
        }

        return time;
    }

    private String setInterfaceState(Interface interf) {
        String state = "<td>";
        switch (interf.getState()) {
            case 1:

                state += "<a href=\"/interfaces.html?stateChange=" + interf.getDevice().getName() + "\" class=\"btn btn-danger\"><i class=\"icon-check icon-white\"></i> Turn Device off";
                break;
            case 0:
                state += "<a href=\"/interfaces.html?stateChange=" + interf.getDevice().getName() + "\" class=\"btn btn-success\"><i class=\"icon-check icon-white\"></i> Turn Device on";
                break;
        }
        state += "</a></td>";
        return state;
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        if (request.getRequestURI().equals("/acl.html")) {

            for (PacketReceiver rec : manager.getReceiverList()) {
                if (rec.getDevice().getName().equals(request.getParameter("port"))) {
                    AccesListItem ali = new AccesListItem(rec.getAcl().getAcl("IN").size() + 1);
                    if (!request.getParameter("srcMAC").equals("")) {
                        ali.setSrcMacAddress(DataTypeHelper.parseStringMacAddress(request.getParameter("srcMAC")));

                    } else {
                        ali.setSrcMacAddress(null);
                    }
                    if (!request.getParameter("dstMAC").equals("")) {
                        ali.setDstMacAddress(DataTypeHelper.parseStringMacAddress(request.getParameter("dstMAC")));

                    } else {
                        ali.setDstMacAddress(null);
                    }
                    if (!request.getParameter("srcIP").equals("")) {
                        ali.setSrcIpAddress(DataTypeHelper.parseStringIpAddress(request.getParameter("srcIP")));

                    } else {
                        ali.setSrcIpAddress(null);
                    }
                    if (!request.getParameter("dstIP").equals("")) {
                        ali.setDstIpAddress(DataTypeHelper.parseStringIpAddress(request.getParameter("srcIP")));

                    } else {
                        ali.setDstIpAddress(null);
                    }
                    if (!request.getParameter("ipv4Protocol").equals("any")) {
                        ali.setProtocol(Integer.parseInt(request.getParameter("ipv4Protocol")));

                    } else {
                        ali.setProtocol(null);
                    }
                    if (!request.getParameter("srcTcpPort").equals("any")) {
                        ali.setSrcPort(Integer.parseInt(request.getParameter("srcTcpPort")));
                    } else {
                        ali.setSrcPort(null);
                    }
                    if (!request.getParameter("dstTcpPort").equals("any")) {
                        ali.setDstPort(Integer.parseInt(request.getParameter("dstTcpPort")));
                    } else {
                        ali.setDstPort(null);
                    }
                    rec.getAcl().addAclItem(ali, request.getParameter("direction"));
                    break;
                }
            }

            response.sendRedirect("/acl.html");
        }
    }

    private String showFilters(String portName, Integer direction) {
        String line = "";
        PacketReceiver port = null;
        for (PacketReceiver receiver : this.manager.getReceiverList()) {
            if (receiver.getDevice().getName().equals(portName)) {
                port = receiver;
            }
        }
        if (port != null) {
            switch (direction) {
                case 0: {
                    line += "  <div class=\"panel-heading\">Filter on Port " + port.getDevice().getName() + "Direction : in </div>\n"
                            + "  <table class=\"table\"><head><tr><th>#</th><th><span class=\"glyphicon glyphicon-resize-small\"></span> Filter item </th><th><span class=\"glyphicon glyphicon-list\"></span> Filter item data</th><th><span class=\"glyphicon glyphicon-refresh\"></span> Count </th>"
                            + "<th> </th>"
                            + "</tr></head>\n";
                    int i = 1;
                    for (AccesListItem item : port.getAcl().getAclIn()) {
                        line += "<tr><td>" + i + "</td>"
                                + "<td>Src MAC Address<br>"
                                + "Dst MAC Address<br>"
                                + "Src IP Address<br>"
                                + "Dst IP address<br>"
                                + "IpV4Protocol<br>"
                                + "Src Port<br>"
                                + "Dst Port<br></td>"
                                + "<td>" + ((item.getSrcMacAddress() == null) ? "Not set" : DataTypeHelper.macAdressConvertor(item.getSrcMacAddress())) + "<br>"
                                + ((item.getDstMacAddress() == null) ? "Not set" : DataTypeHelper.macAdressConvertor(item.getDstMacAddress())) + "<br>"
                                + ((item.getSrcIpAddress() == null) ? "Not set" : DataTypeHelper.ipAdressConvertor(item.getSrcIpAddress())) + "<br>"
                                + ((item.getDstIpAddress() == null) ? "Not set" : DataTypeHelper.ipAdressConvertor(item.getDstIpAddress())) + "<br>"
                                + ((item.getIpv4Protocol() == null) ? "Not set" : item.getIpv4Protocol()) + "<br>"
                                + ((item.getSrcPort() == null) ? "Not set" : item.getSrcPort()) + "<br>"
                                + ((item.getDstPort() == null) ? "Not set" : item.getDstPort()) + "<br>"
                                + "</td>"
                                + "<td> "
                                + item.getBlockCount() + " packets blocked"
                                + "</td>"
                                + "<td><a type=\"button\" class=\"close\" href=\"/acl.html?delete=" + port.getDevice().getName() + "/" + i + "/" + direction + "\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">Close</span></a></td>"
                                + "</tr>";
                        i++;
                    }
                    break;
                }
                case 1: {
                    line += "  <div class=\"panel-heading\">Filter on Port " + port.getDevice().getName() + " Direction : out </div>\n"
                            + "  <table class=\"table\"><head><tr><th>#</th><th><span class=\"glyphicon glyphicon-resize-small\"></span> Filter item </th><th><span class=\"glyphicon glyphicon-list\"></span> Filter item data</th><th><span class=\"glyphicon glyphicon-refresh\"></span> Count </th></tr></head>\n";
                    int i = 1;
                    for (AccesListItem item : port.getAcl().getAclOut()) {
                        line += "<tr><td>" + i + "</td>"
                                + "<td>Src MAC Address<br>"
                                + "Dst MAC Address<br>"
                                + "Src IP Address<br>"
                                + "Dst IP address<br>"
                                + "IpV4Protocol<br>"
                                + "Src Port<br>"
                                + "Dst Port<br></td>"
                                + "<td>" + ((item.getSrcMacAddress() == null) ? "Not set" : DataTypeHelper.macAdressConvertor(item.getSrcMacAddress())) + "<br>"
                                + ((item.getDstMacAddress() == null) ? "Not set" : DataTypeHelper.macAdressConvertor(item.getDstMacAddress())) + "<br>"
                                + ((item.getSrcIpAddress() == null) ? "Not set" : DataTypeHelper.ipAdressConvertor(item.getSrcIpAddress())) + "<br>"
                                + ((item.getDstIpAddress() == null) ? "Not set" : DataTypeHelper.ipAdressConvertor(item.getDstIpAddress())) + "<br>"
                                + ((item.getIpv4Protocol() == null) ? "Not set" : item.getIpv4Protocol()) + "<br>"
                                + ((item.getSrcPort() == null) ? "Not set" : item.getSrcPort()) + "<br>"
                                + ((item.getDstPort() == null) ? "Not set" : item.getDstPort()) + "<br>"
                                + "</td>"
                                + "<td> "
                                + item.getBlockCount() + " packets blocked"
                                + "</td>"
                                + "<td><a type=\"button\" class=\"close\" href=\"/acl.html?delete=" + port.getDevice().getName() + "/" + i + "/" + direction + "\" ><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">Close</span></a></td>"
                                + "</tr>";
                        i++;
                    }
                    break;
                }
            }
        }

        return line;
    }

    private String addStatistics(String portName, Integer direction) {
        String line = "";
        PacketReceiver port = null;

        for (PacketReceiver receiver : this.manager.getReceiverList()) {
            if (receiver.getDevice().getName().equals(portName)) {
                port = receiver;
                break;
            }
        }
        if (port != null) {
            switch (direction) {
                case 0: {
                    for (ProtocolItem item : port.getStatistic().getProtocolListIn()) {
                        line += "<tr><td>" + item.getProtocol() + "</td><td>" + item.getLayer() + "</td><td>" + item.getCount() + "</td></tr>";
                    }
                    break;
                }
                case 1: {
                    for (ProtocolItem item : port.getStatistic().getProtocolListOut()) {
                        line += "<tr><td>" + item.getProtocol() + "</td><td>" + item.getLayer() + "</td><td>" + item.getCount() + "</td></tr>";
                    }
                    break;
                }
            }
        }
        return line;
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        this.currentPage = request.getRequestURI();

        String html = this.getHeaderTemplate();
        switch (this.currentPage) {
            case "/index.html": {
                String pagehtml = "<div class=\"jumbotron\">\n"
                        + "  <h1>Software multilayer switch</h1>\n"
                        + "  <p>PSIP 2014</p>\n"
                        + "  <p><a class=\"btn btn-primary btn-lg\" role=\"button\" href=\"/interfaces.html\" target=\"/interfaces.html\">Start</a></p>\n"
                        + "</div>";
                html += pagehtml;
                break;
            }
            case "/status.html": {
                String pagehtml = "<div class=\"container-fluid\">\n";

                pagehtml += "<div class=\"row\">";
                pagehtml += "<table class=\"table\"><thead><tr><th><span class=\"glyphicon glyphicon-hand-right\"></span> Port Name</th><th><span class=\"glyphicon glyphicon-flag\"></span> Mac address</span></th><th><span class=\"glyphicon glyphicon-time\"></span> Inactive for</th></tr></thead>";
                for (Interface interf : this.manager.getMacTable().getInterfaceList()) {

                    pagehtml += "<tr><td><span class=\"glyphicon glyphicon-fire\"></span> " + interf.getDevice().getName() + "</td><td>" + getMacAddresses(interf) + "</td><td>" + getLastActiveTime(interf) + "</td>";

                }

                pagehtml += "</tr>";
                pagehtml += "</table>";
                pagehtml += "</div></div>";
                html += pagehtml;
                break;
            }
            case "/acl.html": {
                String port = this.manager.getMacTable().getInterfaceList().get(0).getDevice().getName();
                if (request.getParameter("port") != null && !request.getParameter("port").trim().isEmpty()) {
                    port = request.getParameter("port");
                }
                if (request.getParameter("delete") != null && !request.getParameter("delete").trim().isEmpty()) {
                    String deleteSelectedFilter = request.getParameter("delete");
                    System.out.println(deleteSelectedFilter);
                    String sa[] = deleteSelectedFilter.split("/");
                    for (PacketReceiver rcvr : this.manager.getReceiverList()) {
                        if (rcvr.getDevice().getName().equals(sa[0])) {
                            rcvr.getAcl().deleteAclItem(Integer.parseInt(sa[1]) - 1, ((sa[2].equals("0")) ? "IN" : "OUT"));
                        }
                    }
                    response.sendRedirect("/acl.html");
                }
                String pagehtml = ""
                        + "<script type=\"text/javascript\">"
                        + " $(document).ready(function(){"
                        + " $(\"#srcTcpPort\").fadeOut(200);"
                        + "     $(\"#dstTcpPort\").fadeOut(200);"
                        + "$(\"select[name='ipv4Protocol']\").change(function(){"
                        + " var id = $(this).val();"
                        + " if (id === \"6\") {"
                        + "     $(\"#srcTcpPort\").fadeIn(200);"
                        + "     $(\"#dstTcpPort\").fadeIn(200);"
                        + "}"
                        + "});"
                        + "});"
                        + "</script>"
                        + "<br>"
                        + "<button type=\"button\" class=\"btn btn-primary btn-lg\" data-toggle=\"modal\" data-target=\"#myModal\">\n"
                        + "  Add filter item \n"
                        + "</button>\n"
                        + "<div class=\"modal fade\" id=\"myModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"myModalLabel\" aria-hidden=\"true\">\n"
                        + "  <div class=\"modal-dialog\">\n"
                        + "         <div class=\"modal-content\">\n"
                        + "     <form role=\"form\" method=\"POST\" class=\"form-horizontal\">\n"
                        + "             <div class=\"modal-header\">\n"
                        + "                 <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">Close</span></button>\n"
                        + "                 <h4 class=\"modal-title\" id=\"myModalLabel\">Modal title</h4>\n"
                        + "             </div>\n"
                        + "             <div class=\"modal-body\">\n"
                        + "                 <div class=\"form-group\">\n"
                        + "                     <label for=\"port\" class=\"col-sm-4 control-label\">Port</label>\n"
                        + "                         <div class=\"col-sm-8\">\n"
                        + "                             <select name=\"port\">\n"
                        + "                             <option value=\"eth1\">eth1</option>\n"
                        + "                             <option value=\"eth2\">eth2</option>\n"
                        + "                             <option value=\"eth3\">eth3</option>\n"
                        + "                             </select>"
                        + "                         </div>"
                        + "                 </div>"
                        + "                 <div class=\"form-group\">\n"
                        + "                     <label for=\"port\" class=\"col-sm-4 control-label\">Direction</label>\n"
                        + "                         <div class=\"col-sm-8\">\n"
                        + "                             <select name=\"direction\">\n"
                        + "                             <option value=\"IN\">In</option>\n"
                        + "                             <option value=\"OUT\">Out</option>\n"
                        + "                             </select>"
                        + "                         </div>"
                        + "                 </div>"
                        + "                 <div class=\"form-group\">\n"
                        + "                     <label for=\"text\" class=\"col-sm-4 control-label\">src MAC addr</label>\n"
                        + "                     <div class=\"col-sm-8\">\n"
                        + "                         <input type=\"text\" class=\"form-control\" name=\"srcMAC\" placeholder=\"00:00:00:00:00:00\">\n"
                        + "                         <br>"
                        + "                     </div>\n"
                        + "                 </div>\n"
                        + "                 <div class=\"form-group\">\n"
                        + "                     <label for=\"text\" class=\"col-sm-4 control-label\">dst MAC addr</label>\n"
                        + "                     <div class=\"col-sm-8\">\n"
                        + "                         <input type=\"text\" class=\"form-control\" name=\"dstMAC\" placeholder=\"00:00:00:00:00:00\">\n"
                        + "                         <br>"
                        + "                     </div>\n"
                        + "                 </div>\n"
                        + "                 <div class=\"form-group\">\n"
                        + "                     <label for=\"text\" class=\"col-sm-4 control-label\">src IP addr</label>\n"
                        + "                     <div class=\"col-sm-8\">\n"
                        + "                         <input type=\"text\" class=\"form-control\" name=\"srcIP\" placeholder=\"000.000.000.000\">\n"
                        + "                         <br>"
                        + "                     </div>\n"
                        + "                 </div>\n"
                        + "                 <div class=\"form-group\">\n"
                        + "                     <label for=\"text\" class=\"col-sm-4 control-label\">dst IP addr</label>\n"
                        + "                     <div class=\"col-sm-8\">\n"
                        + "                         <input type=\"text\" class=\"form-control\" name=\"dstIP\" placeholder=\"000.000.000.000\">\n"
                        + "                         <br>"
                        + "                     </div>\n"
                        + "                 </div>\n"
                        + "                 <div class=\"form-group\">\n"
                        + "                     <label for=\"Ipv4Protocol\" class=\"col-sm-4 control-label\">IPv4 Protocol</label>\n"
                        + "                         <div class=\"col-sm-8\">\n"
                        + "                             <select name=\"ipv4Protocol\">\n"
                        + "                             <option value=\"any\">ANY</option>\n"
                        + "                             <option value=\"6\">TCP</option>\n"
                        + "                             <option value=\"17\">UDP</option>\n"
                        + "                             <option value=\"1\">ICMP</option>\n"
                        + "                             </select>"
                        + "                         </div>"
                        + "                 </div>"
                        + "                 <div class=\"form-group\" id=\"srcTcpPorts\">\n"
                        + "                     <label for=\"srcTcpPort\" class=\"col-sm-4 control-label\">src TCP port</label>\n"
                        + "                         <div class=\"col-sm-8\">\n"
                        + "                             <select name=\"srcTcpPort\">\n"
                        + "                             <option value=\"any\">ANY</option>\n"
                        + "                             <option value=\"80\">http</option>\n"
                        + "                             <option value=\"22\">ssh</option>\n"
                        + "                             <option value=\"21\">ftp</option>\n"
                        + "                             </select>"
                        + "                         </div>"
                        + "                 </div>"
                        + "                 <div class=\"form-group\" id=\"dstTcpPorts\">\n"
                        + "                     <label for=\"dstTcpPorts\" class=\"col-sm-4 control-label\">dst TCP port</label>\n"
                        + "                         <div class=\"col-sm-8\">\n"
                        + "                             <select name=\"dstTcpPort\">\n"
                        + "                             <option value=\"any\">ANY</option>\n"
                        + "                             <option value=\"80\">http</option>\n"
                        + "                             <option value=\"22\">ssh</option>\n"
                        + "                             <option value=\"21\">ftp</option>\n"
                        + "                             </select>"
                        + "                         </div>"
                        + "                 </div>"
                        + "                 <div class=\"form-group\">\n"
                        + "                     <div class=\"col-sm-offset-2 col-sm-10\">\n"
                        + "                         <div class=\"checkbox\">\n"
                        + "                             <label>\n"
                        + "                                 <input type=\"checkbox\"> Remember me\n"
                        + "                             </label>\n"
                        + "                         </div>\n"
                        + "                     </div>\n"
                        + "                 </div>"
                        + "                 <div class=\"form-group\">\n"
                        + "                     <label for=\"b\" class=\"col-sm-2 control-label\">Protocol</label>\n"
                        + "                         <div class=\"col-sm-10\">\n"
                        + "                             <select name=\"b\">\n"
                        + "                             <option value=\"0800\">IPv4</option>\n"
                        + "                             <option value=\"0806\">ARP</option>\n"
                        + "                             </select>"
                        + "                         </div>"
                        + "                 </div>"
                        + "         </div>\n"
                        + "         <div class=\"modal-footer\">\n"
                        + "             <button type=\"button\" class=\"btn btn-danger\" data-dismiss=\"modal\">Close</button>\n"
                        + "             <button type=\"submit\" class=\"btn btn-success\">Submit</button>\n"
                        + "         </div>\n"
                        + "     </form>"
                        + "       </div>\n"
                        + "  </div>\n"
                        + "</div>"
                        + "<br>";

                pagehtml += "<div class=\"container-fluid\">\n"
                        + "<ul class=\"nav nav-tabs\" role=\"tablist\">\n"
                        + "  <li class=\"dropdown\">\n"
                        + "    <a class=\"dropdown-toggle\" data-toggle=\"dropdown\" href=\"#\">\n"
                        + "      Ports <span class=\"caret\"></span>\n"
                        + "    </a>\n"
                        + "    <ul class=\"dropdown-menu\" role=\"menu\">\n";
                for (Interface interf : this.manager.getMacTable().getInterfaceList()) {
                    pagehtml += "<li role=\"presentation\"><a role=\"menuitem\" tabindex=\"-1\" href=\"acl.html?port=" + interf.getDevice().getName() + "\">" + interf.getDevice().getName() + "</a></li>\n";
                }
                pagehtml += "    </ul>\n"
                        + "  </li></ul>\n";
                pagehtml += "<div class=\"panel panel-default\">\n";
                pagehtml += showFilters(port, 0);
                pagehtml += "</div></table></div><br>";
                pagehtml += "<div class=\"panel panel-default\">\n";
                pagehtml += showFilters(port, 1);
                pagehtml += "</div></table></div><br>";

                html += pagehtml;
                break;
            }
            case "/help.html": {
                break;
            }
            case "/statistics.html": {
                String port = this.manager.getMacTable().getInterfaceList().get(0).getDevice().getName();
                if (request.getParameter("port") != null && !request.getParameter("port").trim().isEmpty()) {
                    port = request.getParameter("port");
                   // response.sendRedirect("/statistics.html");
                }
                if (request.getParameter("flush") != null && !request.getParameter("flush").trim().isEmpty()) {
                    String flush[] = request.getParameter("flush").split("/");
                    for(PacketReceiver rcvr : this.manager.getReceiverList()){
                        if(rcvr.getDevice().getName().equals(flush[0])){
                            rcvr.getStatistic().flushStatistics(flush[1]);
                            response.sendRedirect("/statistics.html?port=" + flush[0]);
                        }
                    }
                    
                }
                String pagehtml = "<div class=\"container-fluid\">\n"
                        + "<ul class=\"nav nav-tabs\" role=\"tablist\">\n"
                        + "  <li class=\"dropdown\">\n"
                        + "    <a class=\"dropdown-toggle\" data-toggle=\"dropdown\" href=\"#\">\n"
                        + "      Ports <span class=\"caret\"></span>\n"
                        + "    </a>\n"
                        + "    <ul class=\"dropdown-menu\" role=\"menu\">\n";
                for (Interface interf : this.manager.getMacTable().getInterfaceList()) {
                    pagehtml += "<li role=\"presentation\"><a role=\"menuitem\" tabindex=\"-1\" href=\"statistics.html?port=" + interf.getDevice().getName() + "\">" + interf.getDevice().getName() + "</a></li>\n";
                }
                pagehtml += "    </ul>\n"
                        + "  </li></ul>\n";
                pagehtml += "<div class=\"panel panel-default\">\n"
                        + "  <div class=\"panel-heading\">Direction: IN on port " + port + "</div>\n"
                        + "  <table class=\"table\"><head><tr><th><span class=\"glyphicon glyphicon-resize-small\"></span> Protocol name</th><th><span class=\"glyphicon glyphicon-list\"></span> RM OSI layer</th><th><span class=\"glyphicon glyphicon-refresh\"></span> Count </th>"
                        + "<th><a type=\"button\" class=\"close\" href=\"/statistics.html?flush=" + port +"/"+ "IN" + "\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">Close</span></a></th>"
                        + "</tr></head>\n";
                pagehtml += addStatistics(port, 0);
                pagehtml += "</div></table></div><br>";
                pagehtml += "<div class=\"panel panel-default\">\n"
                        + "  <div class=\"panel-heading\" >Direction: OUT on port " + port + "</div>\n"
                        + "  <table class=\"table\"><head><tr><th><span class=\"glyphicon glyphicon-resize-small\"></span> Protocol name</th><th><span class=\"glyphicon glyphicon-list\"></span> RM OSI layer</th><th><span class=\"glyphicon glyphicon-refresh\"></span> Count </th>"
                        + "<th><a type=\"button\" class=\"close\" href=\"/statistics.html?flush=" + port +"/"+ "OUT" + "\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">Close</span></a></th>"
                        + "</tr></head>\n";
                pagehtml += addStatistics(port, 1);
                pagehtml += "</div></table></div>";
                html += pagehtml;
                break;
            }
            case "/interfaces.html": {
                if (request.getParameter("stateChange") != null && !request.getParameter("stateChange").trim().isEmpty()) {
                    changeInterfaceState(request.getParameter("stateChange"));
                    response.sendRedirect("/interfaces.html");
                }
                String pagehtml = "<div class=\"container-fluid\">\n"
                        + "<br>";
                pagehtml += "<div class=\"panel panel-default\">\n"
                        + "  <div class=\"panel-heading\">Available interfaces</div>\n"
                        + "  <table class=\"table\"><head><tr><th><span class=\"glyphicon glyphicon-resize-small\"></span> Port Name</th><th><span class=\"glyphicon glyphicon-list\"></span> State</th><th><span class=\"glyphicon glyphicon-refresh\"></span> Change state</th></tr></head>\n";
                for (Interface interf : this.manager.getMacTable().getInterfaceList()) {
                    pagehtml += "<tr><td><span class=\"glyphicon glyphicon-fire\"></span> " + interf.getDevice().getName() + "</td><td>" + getInterfaceState(interf) + "</td>"
                            + setInterfaceState(interf) + "</tr>";
                }
                pagehtml += "</table>\n"
                        + "</div></div></div>";
                html += pagehtml;
                break;
            }
            default: {
                html += this.getNotFoundPage();
                break;
            }
        }
        html += this.getFooterTemplate();

        response.setStatus(HttpServletResponse.SC_OK);
        ByteArrayInputStream htmlBais = new ByteArrayInputStream(html.getBytes("UTF-8"));
        byte[] buffer = new byte[1024];
        while (htmlBais.available() > 0) {
            int rd = htmlBais.read(buffer, 0, buffer.length);
            response.getOutputStream().write(buffer, 0, rd);
        }
    }

    private String getNotFoundPage() {
        String html = "<div class=\"jumbotron\" style=\"margin-top: 15px;\">\n"
                + "  <h1>Software multilayer switch</h1>\n"
                + "  <p>PSIP 2014</p>\n"
                + "  <p><a class=\"btn btn-primary btn-lg\" role=\"button\" href=\"/status.html\" target=\"/status.html\">Start</a></p>\n"
                + "</div>";
        return html;
    }

    private String getHeaderTemplate() {
        String html = "<!DOCTYPE html><html><head><title>Webis</title><meta charset=\"utf-8\">";
        html += this.getLinkedJavascript("/resource/js/jquery.js");
        html += this.getLinkedCss("/resource/css/bootstrap.css");
        html += this.getLinkedCss("/resource/css/bootstrap-theme.css");
        html += this.getLinkedJavascript("/resource/js/bootstrap.js");
        html += "</head><body>";
        html += "<div class=\"container\" style=\"width:800px\">";
        html += "<ul class=\"nav nav-tabs\" role=\"tablist\">";
        // html += "<nav class=\"navbar navbar-inverse\" role=\"navigation\">";

        for (WebMenuItem wmi : this.wmiList) {
            String activeClass = (this.currentPage.equals(wmi.getAddress())) ? " class=\"active\"" : "";
            String iconHtml = (wmi.getIcon() == null) ? "" : "<span class=\"glyphicon glyphicon-" + wmi.getIcon() + "\"></span> ";
            html += "<li" + activeClass + "><a href=\"" + wmi.getAddress() + "\">" + iconHtml + wmi.getTitle() + "</a></li>";
        }
        html += "</ul>";
        return html;
    }

    private String getFooterTemplate() {
        String html
                = "<footer class=\"footer\">Martin Hudec</footer>"
                + "        </div></body></html>";

        return html;
    }

    private String getLinkedJavascript(String address) {
        return "<script type=\"text/javascript\" src=\"" + address + "\"></script>";
    }

    private String getLinkedCss(String address) {
        return "<link rel=\"stylesheet\" href=\"" + address + "\" />";
    }

}
