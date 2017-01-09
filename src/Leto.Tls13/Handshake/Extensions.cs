using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.IO.Pipelines.Text.Primitives;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Leto.Tls13.Certificates;
using Leto.Tls13.Internal;
using Leto.Tls13.KeyExchange;
using Leto.Tls13.Sessions;
using Leto.Tls13.State;

namespace Leto.Tls13.Handshake
{
    public class Extensions
    {
        public static WritableBuffer WriteExtensionList(WritableBuffer buffer, ConnectionState connectionState)
        {
            if (connectionState.State == StateType.SendServerHello)
            {
                //As we don't support PSK yet we can only send the Key share extension
                WriteKeyshare(ref buffer, connectionState);
            }
            if (connectionState.State == StateType.WaitHelloRetry)
            {
                WriteRetryKeyshare(ref buffer, connectionState);
            }
            return buffer;
        }

        public static void WriteRetryKeyshare(ref WritableBuffer buffer, ConnectionState connectionState)
        {
            buffer.WriteBigEndian(ExtensionType.key_share);
            buffer.WriteBigEndian((ushort)sizeof(NamedGroup));
            buffer.WriteBigEndian(connectionState.KeyShare.NamedGroup);
        }

        public static void ReadExtensionList(ReadableBuffer buffer, ConnectionState connectionState)
        {
            ReadableBuffer signatureAlgoBuffer = default(ReadableBuffer);
            ReadableBuffer pskBuffer = default(ReadableBuffer);
            if (buffer.Length < sizeof(ushort))
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
            var listLength = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(sizeof(ushort));
            if (buffer.Length < listLength)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
            while (buffer.Length > 3)
            {
                var extensionType = buffer.ReadBigEndian<ExtensionType>();
                var extensionLength = buffer.Slice(sizeof(ExtensionType)).ReadBigEndian<ushort>();
                buffer = buffer.Slice(sizeof(ExtensionType) + sizeof(ushort));
                if (buffer.Length < extensionLength)
                {
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
                }
                var extensionBuffer = buffer.Slice(0, extensionLength);
                buffer = buffer.Slice(extensionLength);
                switch (extensionType)
                {
                    case ExtensionType.server_name:
                        ReadServerName(extensionBuffer, connectionState);
                        break;
                    case ExtensionType.key_share:
                        ReadKeyshare(extensionBuffer, connectionState);
                        break;
                    case ExtensionType.supported_groups:
                        ReadSupportedGroups(extensionBuffer, connectionState);
                        break;
                    case ExtensionType.supported_versions:
                        signatureAlgoBuffer = extensionBuffer;
                        break;
                    case ExtensionType.signature_algorithms:
                        ReadSignatureScheme(extensionBuffer, connectionState);
                        break;
                    case ExtensionType.application_layer_protocol_negotiation:
                        ReadApplicationProtocolExtension(extensionBuffer, connectionState);
                        break;
                    case ExtensionType.pre_shared_key:
                        pskBuffer = extensionBuffer;
                        break;
                    case ExtensionType.psk_key_exchange_modes:
                        ReadPskKeyExchangeMode(extensionBuffer, connectionState);
                        break;
                    case ExtensionType.certificate_authorities:
                        break;
                }
            }
            //Wait until the end to check the signature, here we select the
            //certificate and this could depend on the server name indication
            //as well as the trusted CA roots.
            if(signatureAlgoBuffer.Length != 0)
            {
                ReadSupportedVersion(signatureAlgoBuffer, connectionState);
            }
            //We only check if we want to use a PSK at the end because we need the 
            //entire state (ciphers okay, and all the other information is correct
            //before we bother
            if(pskBuffer.Length != 0)
            {
                ReadPskKey(pskBuffer, connectionState);
            }
            if (buffer.Length != 0)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
        }

        private static void ReadPskKey(ReadableBuffer pskBuffer, ConnectionState connectionState)
        {
            //throw new NotImplementedException();
        }

        private static void WriteKeyshare(ref WritableBuffer buffer, ConnectionState connectionState)
        {
            buffer.WriteBigEndian(ExtensionType.key_share);
            var totalSize = connectionState.KeyShare.KeyExchangeSize + sizeof(NamedGroup) + sizeof(ushort);
            buffer.WriteBigEndian((ushort)totalSize);
            buffer.WriteBigEndian(connectionState.KeyShare.NamedGroup);
            buffer.WriteBigEndian((ushort)connectionState.KeyShare.KeyExchangeSize);
            connectionState.KeyShare.WritePublicKey(ref buffer);
        }

        private static void ReadServerName(ReadableBuffer buffer, ConnectionState connectionState)
        {
            buffer = BufferExtensions.SliceVector<ushort>(ref buffer);
            while(buffer.Length > 0)
            {
                var nameType = buffer.ReadBigEndian<byte>();
                buffer = buffer.Slice(sizeof(byte));
                var nameBuffer = BufferExtensions.SliceVector<ushort>(ref buffer);
                if(nameType == 0)
                {
                    connectionState.ServerName = nameBuffer.GetUtf8String();
                }
            }
        }

        private static void ReadPskKeyExchangeMode(ReadableBuffer buffer, ConnectionState connectionState)
        {
            buffer = BufferExtensions.SliceVector<byte>(ref buffer);
            while(buffer.Length > 0)
            {
                PskKeyExchangeMode mode;
                buffer = buffer.SliceBigEndian(out mode);
                if(connectionState.PskKeyExchangeMode == PskKeyExchangeMode.none)
                {
                    connectionState.PskKeyExchangeMode = mode;
                }
                else
                {
                    connectionState.PskKeyExchangeMode |= mode;
                }
            }
        }

        private static void ReadApplicationProtocolExtension(ReadableBuffer buffer, ConnectionState connectionState)
        {

        }

        private static void ReadSupportedVersion(ReadableBuffer buffer, ConnectionState connectionState)
        {
            buffer = BufferExtensions.SliceVector<byte>(ref buffer);
            while (buffer.Length > 1)
            {
                ushort version;
                buffer = buffer.SliceBigEndian(out version);
                if (version > 0x0304 && version < 0x7fff)
                {
                    connectionState.Version = version;
                    return;
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.protocol_version);
        }

        private static void ReadSupportedGroups(ReadableBuffer buffer, ConnectionState connectionState)
        {
            if (connectionState.KeyShare != null)
            {
                return;
            }
            buffer = BufferExtensions.SliceVector<ushort>(ref buffer);
            connectionState.KeyShare = connectionState.CryptoProvider.GetKeyshareFromNamedGroups(buffer);
        }

        private static void ReadKeyshare(ReadableBuffer buffer, ConnectionState connectionState)
        {
            if (connectionState.KeyShare?.HasPeerKey == true)
            {
                return;
            }
            buffer = BufferExtensions.SliceVector<ushort>(ref buffer);
            var ks = connectionState.CryptoProvider.GetKeyshareFromKeyshare(buffer);
            connectionState.KeyShare = ks ?? connectionState.KeyShare;
        }

        private static void ReadSignatureScheme(ReadableBuffer buffer, ConnectionState connectionState)
        {
            buffer = BufferExtensions.SliceVector<ushort>(ref buffer);
            while (buffer.Length > 1)
            {
                SignatureScheme scheme;
                buffer = buffer.SliceBigEndian(out scheme);
                var cert = connectionState.CertificateList.GetCertificate(null, scheme);
                if (cert != null)
                {
                    connectionState.Certificate = cert;
                    connectionState.SignatureScheme = scheme;
                    return;
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure);
        }
    }
}
