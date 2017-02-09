using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Certificates;
using Leto.Tls13.KeyExchange;
using Leto.Tls13.State;

namespace Leto.Tls13.Handshake
{
    public class Hello
    {
        public const int RandomLength = 32;

        public static WritableBuffer WriteClientHello(WritableBuffer buffer, IConnectionStateTls13 connectionState)
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
            BufferExtensions.WriteVector<ushort>(ref buffer, ExtensionsWrite.WriteExtensionList, connectionState);
            return buffer;
        }

        public static void ReadClientHello(ref ReadableBuffer readable, IConnectionState connectionState)
        {
            readable = readable.Slice(HandshakeProcessor.HandshakeHeaderSize);
            readable = readable.Slice(sizeof(ushort));
            connectionState.SetClientRandom(readable.Slice(0, RandomLength));
            readable = readable.Slice(RandomLength);
            //We don't support sessions via id so slice and throw
            BufferExtensions.SliceVector<byte>(ref readable);
            //Slice Cipher Suite
            var ciphers = BufferExtensions.SliceVector<ushort>(ref readable);
            if (connectionState.CipherSuite == null)
            {
                connectionState.CipherSuite = connectionState.CryptoProvider.GetCipherSuiteFromExtension(ciphers, connectionState.Version);
            }
            //Skip compression
            BufferExtensions.SliceVector<byte>(ref readable);
        }

        public static void ReadClientHelloTls12(ReadableBuffer readable, ServerStateTls12 connectionState)
        {
            ReadClientHello(ref readable, connectionState);
            if(readable.Length > 0)
            {
                ExtensionsRead.ReadExtensionListTls(ref readable, connectionState);
            }
            connectionState.SignatureScheme = (SignatureScheme)((ushort)connectionState.CipherSuite.HashType << 8 | (ushort)connectionState.CipherSuite.RequiredCertificateType);
            connectionState.Certificate = connectionState.CertificateList.GetCertificate(null, connectionState.SignatureScheme);
            connectionState.SignatureScheme = connectionState.Certificate.ModifySignatureScheme(connectionState.SignatureScheme);
        }

        public static void ReadClientHelloTls13(ReadableBuffer readable, IConnectionStateTls13 connectionState)
        {
            ReadClientHello(ref readable, connectionState);
            if (readable.Length == 0)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.protocol_version, "There is no extensions but we need them for Tls 1.3");
            }
            ExtensionsRead.ReadExtensionListTls13(ref readable, connectionState);
        }

        public static void ReadServerHello(ReadableBuffer readable, IConnectionStateTls13 connectionState)
        {
            var original = readable;
            ushort version, cipherCode;
            readable = readable.Slice(HandshakeProcessor.HandshakeHeaderSize);
            readable = readable.SliceBigEndian(out version);
            //skip random
            readable = readable.Slice(RandomLength);
            readable = readable.SliceBigEndian(out cipherCode);
            connectionState.CipherSuite = connectionState.CryptoProvider.GetCipherSuiteFromCode(cipherCode, connectionState.Version);
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

        public static WritableBuffer SendServerHello12(WritableBuffer buffer, IConnectionState connectionState)
        {
            buffer.Ensure(RandomLength + sizeof(ushort));
            buffer.WriteBigEndian(connectionState.Version);
            var memoryToFill = buffer.Memory.Slice(0, RandomLength);
            connectionState.CryptoProvider.FillWithRandom(memoryToFill);
            connectionState.SetServerRandom(memoryToFill);
            buffer.Advance(RandomLength);
            buffer.WriteBigEndian<byte>(0);
            buffer.WriteBigEndian(connectionState.CipherSuite.CipherCode);
            buffer.WriteBigEndian<byte>(0);
            BufferExtensions.WriteVector<ushort>(ref buffer, ExtensionsWrite.WriteExtensionListTls12, connectionState);
            return buffer;
        }

        public static WritableBuffer SendServerHello13(WritableBuffer buffer, IConnectionStateTls13 connectionState)
        {
            buffer.Ensure(RandomLength + sizeof(ushort));
            buffer.WriteBigEndian(connectionState.Version);
            var memoryToFill = buffer.Memory.Slice(0, RandomLength);
            connectionState.CryptoProvider.FillWithRandom(memoryToFill);
            buffer.Advance(RandomLength);
            buffer.WriteBigEndian(connectionState.CipherSuite.CipherCode);
            BufferExtensions.WriteVector<ushort>(ref buffer, ExtensionsWrite.WriteExtensionList, connectionState);
            return buffer;
        }

        public static WritableBuffer SendHelloRetry(WritableBuffer buffer, IConnectionStateTls13 connectionState)
        {
            if(connectionState.State == StateType.WaitHelloRetry)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "need to send a hello retry but have already sent one");
            }
            buffer.WriteBigEndian(connectionState.Version);
            BufferExtensions.WriteVector<ushort>(ref buffer, ExtensionsWrite.WriteExtensionList, connectionState);
            return buffer;
        }
    }
}
