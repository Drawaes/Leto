using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.KeyExchange;
using Leto.Tls13.State;

namespace Leto.Tls13.Handshake
{
    public class Hello
    {
        private const int RandomLength = 32;

        public static WritableBuffer WriteClientHello(WritableBuffer buffer, IConnectionState connectionState)
        {
            buffer.WriteBigEndian<ushort>(0x0303);
            buffer.Ensure(RandomLength);
            connectionState.CryptoProvider.FillWithRandom(buffer.Memory.Slice(0, RandomLength));
            buffer.Advance(RandomLength);
            //legacy sessionid
            buffer.WriteBigEndian((byte)0);
            connectionState.CryptoProvider.WriteCipherSuites(ref buffer);
            //legacy compression
            buffer.WriteBigEndian((byte)1);
            buffer.WriteBigEndian((byte)0);
            connectionState.KeyShare = connectionState.CryptoProvider.GetDefaultKeyShare();
            BufferExtensions.WriteVector<ushort>(ref buffer, Extensions.WriteExtensionList, connectionState);
            return buffer;
        }

        public static void ReadClientHello(ReadableBuffer readable, IConnectionState connectionState)
        {
            var buffer = readable.Slice(HandshakeProcessor.HandshakeHeaderSize);
            var version = buffer.ReadBigEndian<ushort>();
            //for TLS 1.3 it has to name TLS 1.2 as the legacy version number
            if (version != 0x0303)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.protocol_version, "The version of the client is not TLS 1.2");
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
            }
            //Skip compression
            BufferExtensions.SliceVector<byte>(ref buffer);
            if (buffer.Length == 0)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.protocol_version, "There is no extensions but we need them for Tls 1.3");
            }
            Extensions.ReadExtensionList(ref buffer, connectionState);
        }

        public static void ReadServerHello(ReadableBuffer readable, IConnectionState connectionState)
        {
            var original = readable;
            ushort version, cipherCode;
            readable = readable.Slice(HandshakeProcessor.HandshakeHeaderSize);
            readable = readable.SliceBigEndian(out version);
            if (version != connectionState.Version)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.protocol_version, "Server did not respond with the same version of TLS");
            }
            //skip random
            readable = readable.Slice(RandomLength);
            readable = readable.SliceBigEndian(out cipherCode);
            connectionState.CipherSuite = connectionState.CryptoProvider.GetCipherSuiteFromCode(cipherCode);
            if (connectionState.CipherSuite == null)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter, "Could not get a cipher suite during server hello");
            }
            connectionState.StartHandshakeHash(original);
            readable = BufferExtensions.SliceVector<ushort>(ref readable);
            ExtensionType ext;
            readable = readable.SliceBigEndian(out ext);
            if(ext != ExtensionType.key_share)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter, "There was no keyshare on the server hello");
            }
            readable = BufferExtensions.SliceVector<ushort>(ref readable);
            NamedGroup group;
            readable = readable.SliceBigEndian(out group);
            if(group != connectionState.KeyShare.NamedGroup)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter, "The named group didn't match the keyshare during server hello");
            }
            readable = BufferExtensions.SliceVector<ushort>(ref readable);
            connectionState.KeyShare.SetPeerKey(readable);

        }

        public static WritableBuffer SendServerHello(WritableBuffer buffer, IConnectionState connectionState)
        {
            buffer.Ensure(RandomLength + sizeof(ushort));
            buffer.WriteBigEndian(connectionState.Version);
            var memoryToFill = buffer.Memory.Slice(0, RandomLength);
            connectionState.CryptoProvider.FillWithRandom(memoryToFill);
            buffer.Advance(RandomLength);
            buffer.WriteBigEndian(connectionState.CipherSuite.CipherCode);
            BufferExtensions.WriteVector<ushort>(ref buffer, Extensions.WriteExtensionList, connectionState);
            return buffer;
        }

        public static WritableBuffer SendHelloRetry(WritableBuffer buffer, IConnectionState connectionState)
        {
            if(connectionState.State == StateType.WaitHelloRetry)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "need to send a hello retry but have already sent one");
            }
            connectionState.State = StateType.WaitHelloRetry;
            buffer.WriteBigEndian(connectionState.Version);
            BufferExtensions.WriteVector<ushort>(ref buffer, Extensions.WriteExtensionList, connectionState);
            return buffer;
        }
    }
}
