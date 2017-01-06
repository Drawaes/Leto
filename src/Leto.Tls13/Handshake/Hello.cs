using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.Handshake
{
    public class Hello
    {
        private const int RandomLength = 32;

        public static void ProcessClientHello(ReadableBuffer readable, State.ConnectionState connectionState)
        {
            var buffer = readable.Slice(HandshakeProcessor.HandshakeHeaderSize);
            var version = buffer.ReadBigEndian<ushort>();
            //for TLS 1.3 it has to name TLS 1.2 as the legacy version number
            if(version != 0x0303)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.protocol_version);
            }
            buffer = buffer.Slice(sizeof(ushort));
            //Random is legacy, it is just included in the secrets via the entire message MAC
            buffer = buffer.Slice(RandomLength);
            //We don't support sessions so slice it out and throw it away
            BufferExtensions.SliceVector<byte>(ref buffer);
            //Slice Cipher Suite
            var ciphers = BufferExtensions.SliceVector<ushort>(ref buffer);
            if (connectionState.CipherSuite == null)
            {
                connectionState.CipherSuite = connectionState.CryptoProvider.GetCipherSuiteFromExtension(ciphers);
                if (connectionState.CipherSuite == null)
                {
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure);
                }
                connectionState.StartHandshakeHash(readable);
            }
            else
            {
                connectionState.HandshakeHash.HashData(readable);
            }

            //Skip compression
            BufferExtensions.SliceVector<byte>(ref buffer);
            if(buffer.Length == 0)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.protocol_version);
            }
            Extensions.ProcessExtensionList(buffer, connectionState);
            if(connectionState.KeyShare == null)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter);
            }
            if(connectionState.KeyShare.HasPeerKey)
            {
                connectionState.State = State.StateType.SendServerFlightOne;
            }
            else
            {
                connectionState.State = State.StateType.SendHelloRetry;
            }
        }
    }
}
