//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser.Packets {

    /// <summary>
    /// A Transport Layer Security (TLS) Record
    /// </summary>
    public class TlsRecordPacket : AbstractPacket {
        //http://en.wikipedia.org/wiki/Transport_Layer_Security
        //http://tools.ietf.org/html/rfc2246

        //https://tools.ietf.org/html/draft-davidben-tls-grease-01
        private static readonly HashSet<ushort> GREASE_SET = new HashSet<ushort>(new ushort[] {
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
            0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
            0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
            0xcaca, 0xdada, 0xeaea, 0xfafa
        });

        public enum ContentTypes : byte {
            ChangeCipherSpec = 0x14,
            Alert = 0x15,
            Handshake = 0x16,
            Application = 0x17,
        };

        

        private ContentTypes contentType;
        internal byte VersionMajor { get; }//MSB
        internal byte VersionMinor { get; }//LSB
        private ushort length;//MSB & LSB
        //private HandshakeProtocol handshakeProtocol;

        internal bool TlsRecordIsComplete { get { return PacketEndIndex - PacketStartIndex + 1 == 5 + this.length; } }
        internal ushort Length { get { return this.length; } }
        internal ContentTypes ContentType { get { return this.contentType; } }

        public static new bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            result = null;
            if (!Enum.IsDefined(typeof(ContentTypes), parentFrame.Data[packetStartIndex]))
                return false;

            //verify that the complete TLS record has been received
            ushort length = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 3);
            if (length + 5 > packetEndIndex - packetStartIndex + 1)
                return false;

            try {
                result = new TlsRecordPacket(parentFrame, packetStartIndex, packetEndIndex);
            }
            catch {
                result = null;
            }

            if (result == null)
                return false;
            else
                return true;
        }

        internal TlsRecordPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex) : base(parentFrame, packetStartIndex, packetEndIndex, "TLS Record") {
            this.contentType = (ContentTypes)parentFrame.Data[packetStartIndex];
            this.VersionMajor = parentFrame.Data[packetStartIndex + 1];
            this.VersionMinor = parentFrame.Data[packetStartIndex + 2];
            this.length = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 3);
            this.PacketEndIndex = Math.Min(packetStartIndex + 5 + length - 1, this.PacketEndIndex);

            if (!this.ParentFrame.QuickParse) {
                this.Attributes.Add("Content Type", "" + this.contentType);
                this.Attributes.Add("TLS Version major", "" + VersionMajor);
                this.Attributes.Add("TLS Version minor", "" + VersionMinor);
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;

            //I only care about the hadshake protocol
            if (this.contentType == ContentTypes.Handshake) {
                if (PacketStartIndex + 5 < PacketEndIndex)
                    yield return new RawPacket(ParentFrame, PacketStartIndex + 5, PacketEndIndex);//data in chunks, aka opaque fragment[TLSPlaintext.length] in RFC 5246
            }//end handshake
        }

        public class HandshakePacket : AbstractPacket {

            public const string PACKET_TYPE_DESCRIPTION = "TLS Handshake Protocol";

            public enum MessageTypes : byte {
                HelloRequest = 0x00,
                ClientHello = 0x01,
                ServerHello = 0x02,
                Certificate = 0x0b,

                ServerKeyExchange = 0x0c,
                CertificateRequest = 0x0d,
                ServerHelloDone = 0x0e,
                CertificateVerify = 0x0f,

                ClientKeyExchange = 0x10,
                Finished = 0x14,
            };

            private List<Tuple<byte, byte>> supportedSslVersions;
            public List<string> ApplicationLayerProtocolNegotiationStrings { get; }
            //internal byte VersionMajor { get; }//MSB
            //internal byte VersionMinor { get; }//LSB
            public List<ushort> CipherSuites { get; }
            public List<ushort> ExtensionTypes { get; }
            public List<ushort> SupportedEllipticCurveGroups { get; }
            public List<byte> SupportedEllipticCurvePointFormats { get; }


            public MessageTypes MessageType { get; }
            public uint MessageLength { get; }
            public System.Collections.Generic.List<byte[]> CertificateList { get; }
            public string ServerHostName { get; private set; } = null;

            public Tuple<byte, byte>[] GetSupportedSslVersions() {
                return this.supportedSslVersions.ToArray();
            }
            public string GetAlpnNextProtocolString() {
                return string.Join(", ", this.ApplicationLayerProtocolNegotiationStrings);
            }

            public static IEnumerable<HandshakePacket> GetHandshakes(IEnumerable<TlsRecordPacket> tlsRecordFragments) {
                using (System.IO.MemoryStream handshakeMessageData = new System.IO.MemoryStream()) {
                    Frame firstFrame = null;
                    foreach (TlsRecordPacket record in tlsRecordFragments) {
                        if (record.ContentType != TlsRecordPacket.ContentTypes.Handshake) {
                            yield break;
                        }
                        foreach (AbstractPacket recordData in record.GetSubPackets(false)) {
                            if (firstFrame == null)
                                firstFrame = recordData.ParentFrame;
                            handshakeMessageData.Write(recordData.ParentFrame.Data, recordData.PacketStartIndex, recordData.PacketLength);
                        }
                    }
                    if (handshakeMessageData.Length < 4) {//1 byte type, 3 bytes length
                        yield break;
                    }
                    handshakeMessageData.Position = 1;
                    byte[] lengthBytes = new byte[3];
                    handshakeMessageData.Read(lengthBytes, 0, 3);
                    uint messageLength = Utils.ByteConverter.ToUInt32(lengthBytes, 0, 3);
                    if (handshakeMessageData.Length < messageLength + 4) {
                        yield break;
                    }
                    handshakeMessageData.Position = 0;
                    Frame reassembledFrame = new Frame(firstFrame.Timestamp, handshakeMessageData.ToArray(), firstFrame.FrameNumber);

                    int nextHandshakeOffset = 0;
                    while (nextHandshakeOffset < reassembledFrame.Data.Length) {
                        
                        HandshakePacket handshake;
                        if (TryGetHandshake(reassembledFrame, nextHandshakeOffset, reassembledFrame.Data.Length - 1, out handshake))
                            nextHandshakeOffset = handshake.PacketEndIndex + 1;
                        else
                            yield break;
                        /*
                        try {
                            handshake = new HandshakePacket(reassembledFrame, nextHandshakeOffset, reassembledFrame.Data.Length - 1);
                            nextHandshakeOffset = handshake.PacketEndIndex + 1;
                        }
                        catch {
                            yield break;
                        }
                        */
                        yield return handshake;
                    }
                }
            }

            public static bool TryGetHandshake(Frame parentFrame, int packetStartIndex, int packetEndIndex, out HandshakePacket handshakePacket) {
                handshakePacket = null;
                byte measageTypeValue = parentFrame.Data[packetStartIndex];
                if (!Enum.IsDefined(typeof(MessageTypes), measageTypeValue))
                    return false;//encrypted handshake message

                /* Check the length in the handshake message. Assume it's an
                 * encrypted handshake message if the message would pass
                 * the TLS record boundary. This is a workaround for the
                 * situation where the first octet of the encrypted handshake
                 * message is actually a known handshake message type.
                 */
                uint messageLength = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 1, 3);
                if (packetStartIndex + messageLength + 3 > packetEndIndex)
                    return false;//encrypted handshake message
                //Many encrypted handshakes start with 0x00, but the HelloRequest type (0x00) is typically not used
                if (measageTypeValue == 0 && packetStartIndex + messageLength + 3 != packetEndIndex)
                    return false;//encrypted handshake message
                try {
                    handshakePacket = new HandshakePacket(parentFrame, packetStartIndex, packetEndIndex);
                    return true;
                }
                catch (Exception e) {
                    SharedUtils.Logger.Log("Cannot parse TLS handshake in frame " + parentFrame.FrameNumber + ": " + e.Message, SharedUtils.Logger.EventLogEntryType.Warning);
                    return false;
                }
            }

            //Use TryGetHandshake to create handshake packets!
            private HandshakePacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
                : base(parentFrame, packetStartIndex, packetEndIndex, PACKET_TYPE_DESCRIPTION) {
                this.CertificateList = new List<byte[]>();
                this.supportedSslVersions = new List<Tuple<byte, byte>>();
                this.ApplicationLayerProtocolNegotiationStrings = new List<string>();
                this.CipherSuites = new List<ushort>();
                this.ExtensionTypes = new List<ushort>();
                this.SupportedEllipticCurveGroups = new List<ushort>();
                this.SupportedEllipticCurvePointFormats = new List<byte>();

                this.MessageType = (MessageTypes)parentFrame.Data[packetStartIndex];
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("Message Type", "" + MessageType);
                this.MessageLength = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 1, 3);
                this.PacketEndIndex = (int)(packetStartIndex + 4 + MessageLength - 1);

                if (this.MessageType == MessageTypes.ClientHello) {
                    //this.VersionMajor = parentFrame.Data[PacketStartIndex + 4];
                    //this.VersionMinor = parentFrame.Data[PacketStartIndex + 5];
                    this.supportedSslVersions.Add(new Tuple<byte, byte>(parentFrame.Data[PacketStartIndex + 4], parentFrame.Data[PacketStartIndex + 5]));
                    //byte sessionIdLength = parentFrame.Data[PacketStartIndex + 38];
                    int extensionIndex = PacketStartIndex + 38;
                    byte sessionIdLength = parentFrame.Data[extensionIndex];
                    //ushort cipherSuiteLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, PacketStartIndex + 39 + sessionIdLength);
                    extensionIndex += 1 + sessionIdLength;
                    ushort cipherSuiteLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex);
                    for (int i = 0; i < cipherSuiteLength; i += 2) {
                        this.CipherSuites.Add(Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + 2 + i));
                    }
                    //byte compressionMethodsLength = parentFrame.Data[PacketStartIndex + 41 + cipherSuiteLength];
                    extensionIndex += 2 + cipherSuiteLength;
                    byte compressionMethodsLength = parentFrame.Data[extensionIndex];
                    //ushort extensionsLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, PacketStartIndex + 42 + cipherSuiteLength + compressionMethodsLength);
                    extensionIndex += 1 + compressionMethodsLength;
                    ushort extensionsLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex);
                    //int extensionIndex = PacketStartIndex + 44 + cipherSuiteLength + compressionMethodsLength;
                    extensionIndex += 2;
                    this.ParseExtensions(parentFrame, extensionIndex, extensionsLength);
                    
                }
                else if (this.MessageType == MessageTypes.ServerHello) {
                    /**
                     * https://datatracker.ietf.org/doc/html/rfc2246
                     * struct {
                           ProtocolVersion server_version;
                           Random random;
                           SessionID session_id;
                           CipherSuite cipher_suite;
                           CompressionMethod compression_method;
                       }
                    **/
                    //this.VersionMajor = parentFrame.Data[PacketStartIndex + 4];
                    //this.VersionMinor = parentFrame.Data[PacketStartIndex + 5];
                    this.supportedSslVersions.Add(new Tuple<byte, byte>(parentFrame.Data[this.PacketStartIndex + 4], parentFrame.Data[this.PacketStartIndex + 5]));
                    byte sessionIdLength = parentFrame.Data[this.PacketStartIndex + 38];
                    this.CipherSuites.Add(Utils.ByteConverter.ToUInt16(parentFrame.Data, this.PacketStartIndex + 39 + sessionIdLength));
                    ushort extensionsLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, this.PacketStartIndex + 42 + sessionIdLength);
                    int extensionIndex = this.PacketStartIndex + 44 + sessionIdLength;
                    this.ParseExtensions(parentFrame, extensionIndex, extensionsLength);
                    

                }
                else if (this.MessageType == MessageTypes.Certificate) {
                    uint certificatesLenght = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4, 3);
                    int certificateIndexBase = packetStartIndex + 7;
                    int certificateIndexOffset = 0;
                    while (certificateIndexOffset < certificatesLenght) {
                        //read 3 byte length
                        uint certificateLenght = Utils.ByteConverter.ToUInt32(parentFrame.Data, certificateIndexBase + certificateIndexOffset, 3);
                        certificateIndexOffset += 3;
                        //rest is a certificate
                        byte[] certificate = new byte[certificateLenght];
                        Array.Copy(parentFrame.Data, certificateIndexBase + certificateIndexOffset, certificate, 0, certificate.Length);
                        this.CertificateList.Add(certificate);
                        certificateIndexOffset += certificate.Length;
                    }
                }
            }
            //Server Certificate: http://tools.ietf.org/html/rfc2246 7.4.2

            private void ParseExtensions(PacketParser.Frame parentFrame, int extensionsStartIndex, ushort extensionsLength) {
                int extensionIndex = extensionsStartIndex;
                while (extensionIndex < this.PacketEndIndex && extensionIndex < extensionsStartIndex + extensionsLength) {
                    ushort extensionType = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex);
                    this.ExtensionTypes.Add(extensionType);
                    ushort extensionLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + 2);
                    if (extensionLength > 0) {
                        if (extensionType == 0) {//Server Name Indication rfc6066
                            ushort serverNameListLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + 4);
                            int offset = 6;
                            while (offset < serverNameListLength) {
                                byte serverNameType = parentFrame.Data[extensionIndex + offset];
                                ushort serverNameLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + offset + 1);
                                if (serverNameLength == 0)
                                    break;
                                else {
                                    if (serverNameType == 0) {//host_name(0)
                                        this.ServerHostName = Utils.ByteConverter.ReadString(parentFrame.Data, extensionIndex + offset + 3, serverNameLength);
                                    }
                                    offset += serverNameLength;
                                }
                            }

                        }
                        else if (extensionType == 10) {//Eliptic Curve Groups (for JA3)
                            ushort length = Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + 4);
                            int offset = 6;
                            for (int i = 0; i < length; i += 2) {
                                this.SupportedEllipticCurveGroups.Add(Utils.ByteConverter.ToUInt16(parentFrame.Data, extensionIndex + offset + i));
                            }
                        }
                        else if (extensionType == 11) {//Eliptic Curve Point Formats (for JA3)
                            byte length = parentFrame.Data[extensionIndex + 4];
                            int offset = 5;
                            for (int i = 0; i < length; i++) {
                                this.SupportedEllipticCurvePointFormats.Add(parentFrame.Data[extensionIndex + offset + i]);
                            }
                        }
                        else if (extensionType == 16) {//ALPN
                            int index = extensionIndex + 6;
                            while (index < extensionIndex + extensionLength + 4) {
                                this.ApplicationLayerProtocolNegotiationStrings.Add(Utils.ByteConverter.ReadLengthValueString(parentFrame.Data, ref index, 1));
                            }
                        }
                        else if (extensionType == 43) {//Supported versions
                            //the extensions length is typically an odd number because there's an additional length field before the version byte-tuples
                            int versionTupleStartOffset;
                            if ((extensionLength % 2) == 0)
                                versionTupleStartOffset = 4;
                            else
                                versionTupleStartOffset = 5;
                            for (int offset = versionTupleStartOffset; offset < extensionLength + versionTupleStartOffset - 1; offset += 2) {
                                this.supportedSslVersions.Add(new Tuple<byte, byte>(parentFrame.Data[extensionIndex + offset], parentFrame.Data[extensionIndex + offset + 1]));
                            }
                        }
                    }
                    extensionIndex += 4 + extensionLength;
                }
            }

            public string GetJA3FingerprintFull() {
                /**
                 * https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41
                 * The field order is as follows:
                 * SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
                 * 
                 * Example:
                 * 769,47�53�5�10�49161�49162�49171�49172�50�56�19�4,0�10�11,23�24�25,0
                 **/

                    var v = this.supportedSslVersions.First();
                ushort version = (ushort)((v.Item1 << 8) + v.Item2);

                StringBuilder sb = new StringBuilder();
                sb.Append(version.ToString());
                sb.Append(",");
                sb.Append(String.Join<ushort>("-", this.CipherSuites.Where(cs => !GREASE_SET.Contains(cs))));
                sb.Append(",");
                sb.Append(String.Join<ushort>("-", this.ExtensionTypes.Where(et => !GREASE_SET.Contains(et))));
                sb.Append(",");
                sb.Append(String.Join<ushort>("-", this.SupportedEllipticCurveGroups.Where(ecg => !GREASE_SET.Contains(ecg))));
                sb.Append(",");
                sb.Append(String.Join<byte>("-", this.SupportedEllipticCurvePointFormats));
                return sb.ToString();
            }

            public string GetJA3SFingerprintFull() {
                /**
                 * Version, Accepted Cipher, and List of Extensions.
                 * It then concatenates those values together in order, using a �,� to delimit each field and a �-� to delimit each value in each field.
                 * The field order is as follows:
                 * TLSVersion,Cipher,Extensions
                 * Example:
                 * 769,47,65281�0�11�35�5�16
                 **/
                var v = this.supportedSslVersions.First();
                ushort version = (ushort)((v.Item1 << 8) + v.Item2);
                StringBuilder sb = new StringBuilder();
                sb.Append(version.ToString());
                sb.Append(",");
                sb.Append(String.Join<ushort>("-", this.CipherSuites.Where(cs => !GREASE_SET.Contains(cs))));
                sb.Append(",");
                sb.Append(String.Join<ushort>("-", this.ExtensionTypes.Where(et => !GREASE_SET.Contains(et))));
                return sb.ToString();
            }

            public string GetJA3FingerprintHash() {
                return Utils.ByteConverter.ToMd5HashString(this.GetJA3FingerprintFull());
            }
            public string GetJA3SFingerprintHash() {
                return Utils.ByteConverter.ToMd5HashString(this.GetJA3SFingerprintFull());
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
                yield break;//no sub packets
            }


        }



    }
}
