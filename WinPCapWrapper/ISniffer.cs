//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
using SharedUtils.Pcap;

namespace NetworkWrapper {
    public interface ISniffer : IDisposable {
        PacketReceivedEventArgs.PacketTypes BasePacketType{get;}
        void StartSniffing();
        void StopSniffing();
    }
}
