//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser.PacketHandlers {
    class UnusedTcpSessionProtocolsHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        //private System.Collections.Generic.List<Type> unusedPacketTypes;

        public override Type[] ParsedTypes { get; } = new Type[0];
        /*
        public override bool CanParse(HashSet<Type> packetTypeSet) {
            return packetTypeSet.Overlaps(this.unusedPacketTypes);
        }
        */

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.Unknown; }
        }

        public UnusedTcpSessionProtocolsHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {

            List<Type> unusedPacketTypes = new List<Type> {
                typeof(Packets.NetBiosDatagramServicePacket),
                typeof(Packets.NetBiosNameServicePacket)
            };
            //this.unusedPacketTypes.Add(typeof(Packets.CifsPacket));
            //this.unusedPacketTypes.Add(typeof(Packets.NetBiosPacket));
            //this.unusedPacketTypes.Add(typeof(Packets.NetBiosSessionService));
            //this.unusedPacketTypes.Add(typeof(Packets.OpenFlowPacket));
            this.ParsedTypes = unusedPacketTypes.ToArray();
        }

        #region ITcpSessionPacketHandler Members

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {


            foreach (Packets.AbstractPacket p in packetList) {
                //if(this.unusedPacketTypes.Contains(p.GetType()))
                if (this.ParsedTypes.Contains(p.GetType()))
                    return p.ParentFrame.Data.Length;//it is OK to return larger values than the parsed # bytes as long as there aren't additional trailing packets to parse at the end of the data
            }

            return 0;
        }

        public void Reset() {
            //do nothing since this one holds no state
        }

        #endregion
    }
}
