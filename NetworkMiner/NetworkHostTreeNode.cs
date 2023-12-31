//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace NetworkMiner {


    public class NetworkHostTreeNode : TreeNode, ToolInterfaces.IBeforeExpand{
        private PacketParser.NetworkHost networkHost;
        private Func<System.Net.IPAddress, string> ipLocator;
        private ToolInterfaces.IHostDetailsGenerator hostDetailsGenerator;
        private readonly Func<System.Net.NetworkInformation.PhysicalAddress, System.Net.IPAddress, IEnumerable<NetworkHostTreeNode>> macSiblingsFunction;
        private readonly List<string> nodeKeywords;//for filtering in the GUI
        

        public PacketParser.NetworkHost NetworkHost { get { return this.networkHost; } }

        internal NetworkHostTreeNode(PacketParser.NetworkHost networkHost, Func<System.Net.IPAddress, string> ipLocator, ToolInterfaces.IHostDetailsGenerator hostDetailsGenerator, Func<System.Net.NetworkInformation.PhysicalAddress, System.Net.IPAddress, IEnumerable<NetworkHostTreeNode>> macSiblingsFunction = null) {
            
            this.networkHost=networkHost;
            this.ipLocator=ipLocator;
            this.hostDetailsGenerator = hostDetailsGenerator;
            this.macSiblingsFunction = macSiblingsFunction;
            this.nodeKeywords = new List<string>();

            this.Text=networkHost.ToString();
            this.Nodes.Add("dummie node");

            if(networkHost.SentPackets.Count==0)
                this.ForeColor=System.Drawing.Color.Gray;


            if (this.networkHost.FaviconKey != null)
                this.ImageKey = this.networkHost.FaviconKey;
            else if (this.GetIpImageKey() != null)
                this.ImageKey = this.GetIpImageKey();
            else if (this.GetOsImageKey() != null)
                this.ImageKey = this.GetOsImageKey();
            else {
                lock (networkHost.ExtraDetailsList) {
                    if (networkHost.ExtraDetailsList.Keys.Any(k => k.Contains("Tor ")))
                        this.ImageKey = "tor";
                    else if (networkHost.SentPackets.Count > 0)
                        this.ImageKey = "computer";
                    else
                        this.ImageKey = "white";
                }
            }

            this.SelectedImageKey=this.ImageKey;


            this.ToolTipText="Sent packets: "+networkHost.SentPackets.Count+"\nReceived packets: "+networkHost.ReceivedPackets;

        }

        /// <summary>
        /// Returns the correct imageKey (based on IP) if one exists, otherwise null
        /// </summary>
        /// <returns></returns>
        private string GetIpImageKey() {
            if(networkHost.IpIsReserved)
                return "iana";
            else if(networkHost.IpIsMulticast)
                return "multicast";
            else if(networkHost.IpIsBroadcast)
                return "broadcast";
            else
                return null;
        }
        private string GetOsImageKey() {
            return NetworkHostTreeNode.GetOsImageKey(networkHost);
        }

        public bool AnyKeywordMatches(System.Text.RegularExpressions.Regex regex) {
            if (this.nodeKeywords.Count == 0)
                this.BeforeExpand();//will generate nodes and update keywords list
            lock (this.nodeKeywords) {
                foreach (string kw in this.nodeKeywords)
                    if (regex.IsMatch(kw))
                        return true;
            }
            lock(this.networkHost.ExtraDetailsList) {
                foreach (KeyValuePair<string, string> kvp in this.networkHost.ExtraDetailsList) {
                    if (regex.IsMatch(kvp.Key))
                        return true;
                    if (regex.IsMatch(kvp.Value))
                        return true;
                }
            }
            //the HostDetailCollection doesn't need a lock, a new collection is generated when accessed
            System.Collections.Specialized.NameValueCollection details = this.networkHost.GetHostDetailCollection();
            foreach (string key in details.Keys) {
                if (regex.IsMatch(key))
                    return true;
                if (regex.IsMatch(details[key]))
                    return true;
            }

            /*
            foreach (string domain in this.NetworkHost.HostNames)
                if (regex.IsMatch(domain))
                    return true;
            foreach (string ja3 in this.NetworkHost.Ja3Hashes)
                if (regex.IsMatch(ja3))
                    return true;
            */
            return false;
        }

        public static string GetOsImageKey(PacketParser.NetworkHost networkHost) {
            if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.Windows)
                return "windows";
            else if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.Linux)
                return "linux";
            else if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.MacOS || networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.Apple_iOS)
                return "apple";
            else if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.UNIX)
                return "unix";
            else if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.FreeBSD)
                return "freebsd";
            else if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.NetBSD)
                return "netbsd";
            else if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.Solaris)
                return "solaris";
            else if(networkHost.OS==PacketParser.NetworkHost.OperatingSystemID.Cisco)
                return "cisco";
            else if (networkHost.OS == PacketParser.NetworkHost.OperatingSystemID.Android)
                return "android";
            else if (networkHost.OS == PacketParser.NetworkHost.OperatingSystemID.ABB)
                return "abb";
            else if (networkHost.OS == PacketParser.NetworkHost.OperatingSystemID.Siemens)
                return "siemens";
            else if (networkHost.OS == PacketParser.NetworkHost.OperatingSystemID.ICS_device)
                return "ICS device";
            else
                return null;
        }

        public void BeforeExpand() {
            this.Nodes.Clear();
            TreeNode ipNode=new TreeNode("IP: "+networkHost.IPAddress.ToString());

            if(networkHost.IpIsReserved)
                ipNode.Text+=" (IANA Reserved)";
            if(networkHost.IpIsMulticast)
                ipNode.Text+=" (Multicast)";
            if(networkHost.IpIsBroadcast)
                ipNode.Text+=" (Broadcast)";

            if(GetIpImageKey()!=null)
                ipNode.ImageKey=GetIpImageKey();
            ipNode.SelectedImageKey=ipNode.ImageKey;

            ipNode.Tag = networkHost.IPAddress.ToString();
 
            this.Nodes.Add(ipNode);

            if (networkHost.MacAddress != null) {

                //TreeNode nicNode = this.Nodes.Add("nic", "MAC: " + networkHost.MacAddress.ToString() + " (" + macVendor + ")", "nic", "nic");
                TreeNode nicNode = this.Nodes.Add("nic", "MAC: " + networkHost.MacAddress.ToString(), "nic", "nic");
                nicNode.Tag = networkHost.MacAddress.ToString();
                if(this.macSiblingsFunction != null) {
                    foreach(NetworkHostTreeNode sibling in this.macSiblingsFunction.Invoke(this.networkHost.MacAddress, this.networkHost.IPAddress)) {
                        if (sibling?.NetworkHost != null) {
                            TreeNodeLink link = new TreeNodeLink(sibling.NetworkHost.IPAddress, sibling);
                            nicNode.Nodes.Add(link);
                        }
                    }
                }

                TreeNode nicVendorNode;
                string macVendor;
                if (PacketParser.Fingerprints.MacCollection.GetMacCollection(System.IO.Path.GetFullPath(System.Windows.Forms.Application.ExecutablePath)).TryGetMacVendor(networkHost.MacAddress, out macVendor)) {
                    nicVendorNode = this.Nodes.Add("nicVendor", "NIC Vendor: " + macVendor, "nic", "nic");
                    nicVendorNode.Tag = macVendor;
                }
                else {
                    nicVendorNode = this.Nodes.Add("nicVendor", "NIC Vendor: " + "Unknown", "nic", "nic");
                    nicVendorNode.Tag = "";
                }
                if (PacketParser.Fingerprints.MacAges.GetMacAges(System.IO.Path.GetFullPath(System.Windows.Forms.Application.ExecutablePath)).TryGetDateAndSource(networkHost.MacAddress.ToString(), out DateTime date, out string source)) {
                    this.Nodes.Add("macAge", "MAC Age: " + date.ToString("yyyy'-'MM'-'dd"), "nic", "nic");
                }
            }
            else {
                TreeNode nicNode = this.Nodes.Add("nic", "MAC: Unknown", "nic", "nic");
                nicNode.Tag = "Unknown";
                TreeNode nicVendorNode = this.Nodes.Add("nicVendor", "NIC Vendor: " + "Unknown", "nic", "nic");
                nicVendorNode.Tag = "";
            }
            TreeNode hostnameNode = this.Nodes.Add("Hostname: "+networkHost.HostName);
            hostnameNode.Tag = networkHost.HostName;


            if(this.ipLocator!=null) {
                string countryString = ipLocator.Invoke(networkHost.IPAddress);
                if (countryString != null && countryString.Length > 0) {
                    TreeNode geoIpNode = this.Nodes.Add("GeoIP", "GeoIP: " + countryString);
                    geoIpNode.Tag = countryString;
                    
                }

            }

            TreeNode osNode=this.Nodes.Add("OS", "OS: "+networkHost.OS.ToString(), GetOsImageKey(), GetOsImageKey());
            osNode.Tag = networkHost.OS.ToString();
            lock(networkHost.OsFingerprinters)
                foreach (PacketParser.Fingerprints.IOsFingerprinter fingerprinter in networkHost.OsFingerprinters) {
                    osNode.Nodes.Add(fingerprinter.Name, fingerprinter.Name+": "+networkHost.GetOsDetails(fingerprinter));
                }
            if (networkHost.Ttl > 0) {
                TreeNode ttlNode = this.Nodes.Add("TTL: " + networkHost.Ttl + " (distance: " + networkHost.TtlDistance + ")");
                ttlNode.Tag = networkHost.TtlDistance.ToString();
            }
            else {
                TreeNode ttlNode = this.Nodes.Add("TTL: Unknown");
                ttlNode.Tag = "Unknown";
            }

            this.Nodes.Add(new ServiceListTreeNode(networkHost));

            //add packets
            this.Nodes.Add(new SentReceivedTreeNode(networkHost, true));
            this.Nodes.Add(new SentReceivedTreeNode(networkHost, false));

            //add sessions
            this.Nodes.Add(new SessionListTreeNode(networkHost, true));
            this.Nodes.Add(new SessionListTreeNode(networkHost, false));

            //Details

            if (this.hostDetailsGenerator != null && !this.networkHost.ExtraDetailsList.ContainsKey(this.hostDetailsGenerator.GetDefaultKeyName())) {
                System.Collections.Specialized.NameValueCollection extraDetails = this.hostDetailsGenerator.GetExtraDetails(this.networkHost.IPAddress);

                for (int i = 0; i < extraDetails.Count; i++) {
                    lock (this.networkHost.ExtraDetailsList)
                        if (!this.networkHost.ExtraDetailsList.ContainsKey(extraDetails.Keys[i]))
                            this.networkHost.ExtraDetailsList.Add(extraDetails.Keys[i], extraDetails[i]);
                }
            }
            var details = this.networkHost.GetHostDetailCollection();
            if (details.Count>0) {
                this.Nodes.Add(new HostDetailListTreeNode(details));
            }
            lock(this.nodeKeywords) {
                this.AddNodeTextRecursive(this);
            }
        }

        private void AddNodeTextRecursive(TreeNode node) {
            //this.keywords should have been locked before running this function!
            if (!string.IsNullOrEmpty(node?.Text))
                this.nodeKeywords.Add(node.Text);
            foreach (TreeNode childNode in node?.Nodes?.OfType<TreeNode>()) {
                this.AddNodeTextRecursive(childNode);
            }
        }

        internal class TreeNodeLink : TreeNode {
            internal TreeNode LinkedTreeNode { get; }


            public TreeNodeLink(System.Net.IPAddress ip, TreeNode linkedTreeNode) : base(ip.ToString() + " (same MAC address)") {
                if (linkedTreeNode.TreeView != null) {
                    this.NodeFont = new System.Drawing.Font(linkedTreeNode.TreeView.Font, System.Drawing.FontStyle.Underline);
                    this.LinkedTreeNode = linkedTreeNode;
                }
#if DEBUG
                else
                    System.Diagnostics.Debugger.Break();
#endif
                
            }
        }

        internal class ServiceListTreeNode : TreeNode, ToolInterfaces.IBeforeExpand {
            private PacketParser.NetworkHost host;

            internal ServiceListTreeNode(PacketParser.NetworkHost host) {
                this.host=host;
                {
                    StringBuilder sb=new StringBuilder("Open TCP Ports:");
                    foreach(uint port in host.OpenTcpPorts) {
                        sb.Append(" "+port);
                        if(host.NetworkServiceMetadataList.ContainsKey((ushort)port) && host.NetworkServiceMetadataList[(ushort)port].ApplicationLayerProtocol != PacketParser.ApplicationLayerProtocol.Unknown)
                            sb.Append(" ("+host.NetworkServiceMetadataList[(ushort)port].ApplicationLayerProtocol.ToString()+")");
                    }

                    this.Text=sb.ToString();
                    //this.Nodes.Add(sb.ToString());
                }
                if(host.NetworkServiceMetadataList.Count > 0) {
                    this.Nodes.Add("dummie node");//so that it can be expanded
                }
            }
            #region IBeforeExpand Members

            public void BeforeExpand() {
                this.Nodes.Clear();
                //List<NetworkSession> serviceList;
                //I want the services sorted by port, so I'll have to complicate things a bit
                //SortedList<string, TreeNode> sessionServerNodes=new SortedList<string, TreeNode>();
                lock (host.NetworkServiceMetadataList) {
                    foreach (PacketParser.NetworkServiceMetadata networkService in host.NetworkServiceMetadataList.Values) {
                        StringBuilder sb = new StringBuilder("TCP " + networkService.TcpPort);
                        if (networkService.ApplicationLayerProtocol != PacketParser.ApplicationLayerProtocol.Unknown)
                            sb.Append(" (" + networkService.ApplicationLayerProtocol.ToString() + ")");
                        sb.Append(" - " +
                            "Entropy (in \\ out): " + networkService.IncomingTraffic.CalculateEntropy().ToString("#.00") + " \\ " + networkService.OutgoingTraffic.CalculateEntropy().ToString("#.00") +//wildcard integers and 2 decimals?
                            " Typical data (in \\ out): " + networkService.IncomingTraffic.GetTypicalData() + " \\ " + networkService.OutgoingTraffic.GetTypicalData());
                        this.Nodes.Add(sb.ToString());
                    }
                }

            }

            #endregion
        }

        internal class SessionListTreeNode : TreeNode, ToolInterfaces.IBeforeExpand {
            private PacketParser.NetworkHost host;
            private bool sessionsAreIncoming;
            internal SessionListTreeNode(PacketParser.NetworkHost host, bool sessionsAreIncoming) {
                this.host=host;
                this.sessionsAreIncoming=sessionsAreIncoming;
                if(sessionsAreIncoming){
                    int sessionCount=host.IncomingSessionList.Count;
                    this.Text="Incoming sessions: "+sessionCount;
                    if(sessionCount>0) {
                        this.Nodes.Add("dummie node");
                        this.ImageKey="incoming";
                    }
                }
                else{
                    int sessionCount=host.OutgoingSessionList.Count;
                    this.Text="Outgoing sessions: "+sessionCount;
                    if(sessionCount>0) {
                        this.Nodes.Add("dummie node");
                        this.ImageKey="outgoing";
                    }
                }
                this.SelectedImageKey=this.ImageKey;
            }

            public void BeforeExpand() {
                this.Nodes.Clear();
                List<PacketParser.NetworkTcpSession> sessionList;
                if(sessionsAreIncoming)//host is server
                    sessionList=host.IncomingSessionList;
                else
                    sessionList=host.OutgoingSessionList;
                //I want the session servers sorted by IP and port, so I'll have to complicate things a bit
                SortedList<string, TreeNode> sessionServerNodes=new SortedList<string, TreeNode>();
                lock (sessionList) {
                    foreach (PacketParser.NetworkTcpSession networkSession in sessionList) {
                        byte[] ipBytes = networkSession.ServerHost.IPAddress.GetAddressBytes();
                        string sessionServerKey = "";
                        foreach (byte b in ipBytes)
                            sessionServerKey += b.ToString("X2");
                        sessionServerKey += networkSession.ServerTcpPort.ToString("X2");
                        string sessionServerString = "Server: " + networkSession.ServerHost.ToString() + " TCP " + networkSession.ServerTcpPort;
                        if (!sessionServerNodes.ContainsKey(sessionServerKey))
                            sessionServerNodes.Add(sessionServerKey, new TreeNode(sessionServerString));
                        sessionServerNodes[sessionServerKey].Nodes.Add(networkSession.ToString());
                    }
                }
                foreach(TreeNode sessionServerNode in sessionServerNodes.Values)
                    this.Nodes.Add(sessionServerNode);
            }
        }

        internal class SentReceivedTreeNode : TreeNode/*, ToolInterfaces.IBeforeExpand*/ {
            private PacketParser.NetworkHost host;
            private bool hostIsSender;
            //private TreeNode treeNode;
            internal SentReceivedTreeNode(PacketParser.NetworkHost host, bool hostIsSender) {
                this.host=host;
                this.hostIsSender=hostIsSender;
                if(hostIsSender) {
                    this.Text="Sent: "+host.SentPackets.ToString();
                    this.ImageKey="sent";

                }
                else {//host is reciever
                    this.Text="Received: "+host.ReceivedPackets.ToString();
                    this.ImageKey="received";
                }
                this.SelectedImageKey=this.ImageKey;
            }

        }


        internal class HostDetailListTreeNode : TreeNode, ToolInterfaces.IBeforeExpand {
            private System.Collections.Specialized.NameValueCollection details;

            internal HostDetailListTreeNode(System.Collections.Specialized.NameValueCollection details) {
                this.details=details;
                this.Text="Host Details";
                this.ImageKey="details";
                this.SelectedImageKey = "details";
                this.Nodes.Add("dummie node");//so that it can be expanded
            }

            #region IBeforeExpand Members

            public void BeforeExpand() {
                this.Nodes.Clear();
                for(int i=0; i<details.Count; i++) {
                    TreeNode tn = this.Nodes.Add(details.Keys[i]+" : "+details[i]);
                    if (details.Keys[i].StartsWith("favicon")) {
                        tn.ImageKey = details[i];
                    }

                }
            }

            #endregion
        }
        

    }
}
