using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public class Capwap : AbstractPacket {

        //https://www.rfc-editor.org/rfc/rfc5415.html

        private byte headerVersion, headerType;
        private byte wirelessBindingID;
        private int headerLength;

        enum CapwapType : byte {
            Capwap = 0,
            DTLS = 1
        }
        enum WirelessBindingID : byte {
            Reserved = 0,
            IEEE_802_11 = 1,
            Reserved2 = 2,
            EPCGlobal = 3
        }


        internal Capwap(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "CAPWAP") {
            this.headerVersion = (byte)(parentFrame.Data[PacketStartIndex] >> 4);
            this.headerType = (byte)(parentFrame.Data[PacketStartIndex] & 0x0f);

            if (this.headerType == (byte)CapwapType.DTLS) {
                this.headerLength = 4;
            }
            else if (this.headerType == (byte)CapwapType.Capwap) {
                //parse capwap header
                /**
                0                   1                   2                   3
                0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |CAPWAP Preamble|  HLEN   |   RID   | WBID    |T|F|L|W|M|K|Flags|
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |          Fragment ID          |     Frag Offset         |Rsvd |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |                 (optional) Radio MAC Address                  |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |            (optional) Wireless Specific Information           |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                |                        Payload ....                           |
                +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                */
                this.headerLength = 4 * (parentFrame.Data[PacketStartIndex + 1] >> 3);
                this.wirelessBindingID = (byte)((parentFrame.Data[PacketStartIndex + 2] >> 1) & 0x1f);
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            if (this.headerType == (byte)(CapwapType.Capwap) && this.wirelessBindingID == (byte)(WirelessBindingID.IEEE_802_11)) {
                IEEE_802_11Packet iee80211 = new IEEE_802_11Packet(this.ParentFrame, this.PacketStartIndex + this.headerLength, this.PacketEndIndex, true);
                yield return iee80211;
                foreach (AbstractPacket subPacket in iee80211.GetSubPackets(false))
                    yield return subPacket;
            }
        }
    }
}
