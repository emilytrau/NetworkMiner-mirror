//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    public class TcpPortProtocolFinder : ISessionProtocolFinder {

        public static IEnumerable<ApplicationLayerProtocol> GetProbableApplicationLayerProtocols(ushort serverPort, ushort clientPort, bool clientMightBeServer = false) {
            TcpPortProtocolFinder finder = new TcpPortProtocolFinder(null, null, clientPort, serverPort, 0, DateTime.MinValue, null, clientMightBeServer);
            return finder.GetProbableApplicationLayerProtocols();
        }

        public static readonly (ApplicationLayerProtocol protocol, HashSet<ushort> serverPorts)[] PROTOCOL_PORTS = {
            (ApplicationLayerProtocol.Http,
                new HashSet<ushort> {
                    80,
                    631,//IPP
                    3000,//WEBrick
                    5985,
                    8000,//WEBrick
                    8080,
                    3128,//TCP 3128 = Squid proxy: http://www.squid-cache.org/Doc/config/http_port/
                    10080,
                    11371
                }
            ),
            (ApplicationLayerProtocol.Ssl,
                new HashSet<ushort> {//From: http://www.rickk.com/sslwrap/
                    443,//https 443/tcp     # http protocol over TLS/SSL
                    465,//smtps 465/tcp     # smtp protocol over TLS/SSL
                    563,//nntps 563/tcp     # nttp protocol over TLS/SSL
                    614,//sshell 	614 	tcp 	SSLshell
                    636,//ldaps 	636 	tcp 	ldap protocol over TLS/SSL (was sldap)
                    853,//dns over tls
                    989,//ftps-data 989/tcp # ftp protocol, data, over TLS/SSL
                    990,//ftps 990/tcp      # ftp protocol, control, over TLS/SSL
                    992,//telnets 992/tcp   # telnet protocol over TLS/SSL
                    993,//imaps 993/tcp     # imap4 protocol over TLS/SSL
                    994,//ircs 994/tcp      # irc protocol over TLS/SSL
                    995,//pop3s 995/tcp     # POP3 protocol over TLS/SSL
                    5061,
                    5223,
                    5986,
                    8170,
                    8443,
                    9001,
                    9030,
                    10443
                }
            ),
        (ApplicationLayerProtocol.Meterpreter,
                new HashSet<ushort> {
                    3333,
                    4444,
                    4445,
                    4446,
                    4447,
                    4448,
                    4449,
                    4545,
                    5555,
                    6666,
                    7777,
                    8888,
                    9999
                }
            )
        };

        public static IEnumerable<ApplicationLayerProtocol> GetDefaultProtocols(ushort clientPort, ushort serverPort, bool clientMightBeServer = false, NetworkHost client = null, NetworkHost server = null) {
            if (serverPort == 21 || serverPort == 8021)
                yield return ApplicationLayerProtocol.FtpControl;
            if (serverPort == 22)
                yield return ApplicationLayerProtocol.Ssh;
            if (serverPort == 25 || serverPort == 587)
                yield return ApplicationLayerProtocol.Smtp;
            if (serverPort == 53)
                yield return ApplicationLayerProtocol.Dns;
            if (serverPort == 80 || serverPort == 10080)
                yield return ApplicationLayerProtocol.Http2;
            if (serverPort == 88 || clientPort == 88)
                yield return ApplicationLayerProtocol.Kerberos;
            if (serverPort == 102 || serverPort == 3389)//102 = Siemens S7, 3389 = RDP
                yield return ApplicationLayerProtocol.Tpkt;
            if (serverPort == 110)
                yield return ApplicationLayerProtocol.Pop3;
            if (serverPort == 137 ||clientPort == 137)
                yield return ApplicationLayerProtocol.NetBiosNameService;
            if (serverPort == 143 || serverPort == 220)
                yield return ApplicationLayerProtocol.Imap;
            if (serverPort == 139 || clientPort == 139)
                yield return ApplicationLayerProtocol.NetBiosSessionService;
            if (serverPort == 445 ||clientPort == 445)
                yield return ApplicationLayerProtocol.NetBiosSessionService;
            if (serverPort == 515)
                yield return ApplicationLayerProtocol.Lpd;
            if (serverPort == 1080 ||
                serverPort == 4145 ||
                serverPort == 9040 ||
                serverPort == 9050 ||
                serverPort == 9051 ||
                serverPort == 9150 ||
                (server != null && System.Net.IPAddress.IsLoopback(server.IPAddress) && serverPort > 1024))
                yield return ApplicationLayerProtocol.Socks;
            if (serverPort == 1433)
                yield return ApplicationLayerProtocol.TabularDataStream;
            if (serverPort == 4070)
                yield return ApplicationLayerProtocol.SpotifyServerProtocol;
            if (serverPort == 194 || (serverPort >= 6660 && serverPort <= 6670) || serverPort == 7777 || (serverPort >= 6112 && serverPort <= 6119))
                yield return ApplicationLayerProtocol.Irc;
            if (serverPort == 6633 || clientPort == 6633)
                yield return ApplicationLayerProtocol.OpenFlow;
            if (serverPort == 5190 || clientPort == 5190 || clientPort == 443 || serverPort == 443)
                yield return ApplicationLayerProtocol.Oscar;
            if (serverPort == 5190 || clientPort == 5190 || clientPort == 443 || serverPort == 443)
                yield return ApplicationLayerProtocol.OscarFileTransfer;
            if (serverPort == 5060 || clientPort == 5060)
                yield return ApplicationLayerProtocol.Sip;
            if (serverPort == 2404 || clientPort == 2404)
                yield return ApplicationLayerProtocol.IEC_104;
            if (serverPort == 502 || clientPort == 502)
                yield return ApplicationLayerProtocol.ModbusTCP;

            foreach ((ApplicationLayerProtocol protocol, HashSet<ushort> portSet) in PROTOCOL_PORTS) {
                if (portSet.Contains(serverPort))
                    yield return protocol;
                else if (clientMightBeServer && portSet.Contains(clientPort))
                    yield return protocol;
            }
        }


        private readonly List<ApplicationLayerProtocol> probableProtocols;
        private ApplicationLayerProtocol confirmedProtocol;
        private readonly long startFrameNumber;
        private readonly DateTime startTimestamp;
        private readonly PacketHandler packetHandler;




        public NetworkHost Client { get; }
        public NetworkHost Server { get; }

        public ushort ClientPort { get; }
        public ushort ServerPort { get; }

        public NetworkFlow Flow { get; }

        public ApplicationLayerProtocol GetConfirmedApplicationLayerProtocol() {
            return this.confirmedProtocol;
        }

        public void SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol value, bool setAsPersistantProtocolOnServerEndPoint) {
            if (this.confirmedProtocol == ApplicationLayerProtocol.Unknown) {
                this.confirmedProtocol = value;
                this.packetHandler.OnSessionDetected(new PacketParser.Events.SessionEventArgs(this.Flow, value, this.startFrameNumber));
                if (setAsPersistantProtocolOnServerEndPoint && value != ApplicationLayerProtocol.Unknown) {
                    lock (this.Server.NetworkServiceMetadataList)
                        if (this.Server.NetworkServiceMetadataList.ContainsKey(this.ServerPort))
                            this.Server.NetworkServiceMetadataList[this.ServerPort].ApplicationLayerProtocol = value;
                }
            }
            else if (value != PacketParser.ApplicationLayerProtocol.Unknown) {
                this.confirmedProtocol = value;
            }
        }

        internal TcpPortProtocolFinder(NetworkFlow flow, long startFrameNumber, PacketHandler packetHandler) : this(flow.FiveTuple.ClientHost, flow.FiveTuple.ServerHost, flow.FiveTuple.ClientPort, flow.FiveTuple.ServerPort, startFrameNumber, flow.StartTime, packetHandler) {
            this.Flow = flow;
        }

        internal TcpPortProtocolFinder(NetworkFlow flow, long startFrameNumber, PacketHandler packetHandler, NetworkHost nextHopServer, ushort nextHopServerPort) : this(flow.FiveTuple.ClientHost, nextHopServer, flow.FiveTuple.ClientPort, nextHopServerPort, startFrameNumber, flow.StartTime, packetHandler) {
            this.Flow = flow;
        }

        private TcpPortProtocolFinder(NetworkHost client, NetworkHost server, ushort clientPort, ushort serverPort, long startFrameNumber, DateTime startTimestamp, PacketHandler packetHandler, bool clientMightBeServer = false) {
            this.probableProtocols = new List<ApplicationLayerProtocol>();
            this.confirmedProtocol = ApplicationLayerProtocol.Unknown;
            this.Client = client;
            this.Server = server;
            this.ClientPort = clientPort;
            this.ServerPort = serverPort;

            this.startFrameNumber = startFrameNumber;
            this.startTimestamp = startTimestamp;

            this.packetHandler = packetHandler;

            this.probableProtocols.AddRange(GetDefaultProtocols(this.ClientPort, this.ServerPort, clientMightBeServer, this.Client, this.Server));
        }

        public void AddPacket(PacketParser.Packets.TcpPacket tcpPacket, NetworkHost source, NetworkHost destination) {
            //do nothing
        }

        public IEnumerable<ApplicationLayerProtocol> GetProbableApplicationLayerProtocols() {
            if (this.confirmedProtocol != ApplicationLayerProtocol.Unknown) {
                yield return this.confirmedProtocol;
                if (this.confirmedProtocol == PacketParser.ApplicationLayerProtocol.Http)
                    yield return PacketParser.ApplicationLayerProtocol.Http2;
                else if (this.confirmedProtocol == PacketParser.ApplicationLayerProtocol.Http2)
                    yield return PacketParser.ApplicationLayerProtocol.Http;
            }
            else {
                foreach (ApplicationLayerProtocol p in this.probableProtocols)
                    yield return p;
            }
        }

        
    }
}
