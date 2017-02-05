using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Certificates;
using Leto.Tls13.Sessions;
using Leto.Tls13.State;

namespace Leto.Tls13.Handshake
{
    public class ExtensionsRead
    {
        public static void ReadExtensionListTls13(ref ReadableBuffer buffer, IConnectionStateTls13 connectionState)
        {
            ReadableBuffer signatureAlgoBuffer = default(ReadableBuffer);
            ReadableBuffer pskBuffer = default(ReadableBuffer);
            if (buffer.Length < sizeof(ushort))
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, $"Extension list is not at least the size of a ushort");
            }
            var listLength = buffer.ReadBigEndian<ushort>();
            buffer = buffer.Slice(sizeof(ushort));
            if (buffer.Length < listLength)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "The extension list is not as long as the header says");
            }
            var currentbuffer = buffer.Slice(0, listLength);
            buffer = buffer.Slice(currentbuffer.End);
            while (currentbuffer.Length > 3)
            {
                var extensionType = currentbuffer.ReadBigEndian<ExtensionType>();
                var extensionLength = currentbuffer.Slice(sizeof(ExtensionType)).ReadBigEndian<ushort>();
                currentbuffer = currentbuffer.Slice(sizeof(ExtensionType) + sizeof(ushort));
                if (currentbuffer.Length < extensionLength)
                {
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, $"The extension of type {extensionType} is too long for the remaining buffer");
                }
                var extensionBuffer = currentbuffer.Slice(0, extensionLength);
                currentbuffer = currentbuffer.Slice(extensionLength);
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
                    case ExtensionType.signature_algorithms:
                        signatureAlgoBuffer = extensionBuffer;
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
                    case ExtensionType.early_data:
                        ReadEarlyData(extensionBuffer, connectionState);
                        break;
                }
            }
            //Wait until the end to check the signature, here we select the
            //certificate and this could depend on the server name indication
            //as well as the trusted CA roots.
            if (signatureAlgoBuffer.Length != 0)
            {
                ReadSignatureScheme(signatureAlgoBuffer, connectionState);
            }
            //We only check if we want to use a PSK at the end because we need the 
            //entire state (ciphers okay, and all the other information is correct
            //before we bother
            if (pskBuffer.Length != 0)
            {
                ReadPskKey(pskBuffer, connectionState);
            }
            if (currentbuffer.Length != 0)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "there was data after the extension list which is invalid");
            }
        }

        public static void ReadExtensionListTls(ref ReadableBuffer buffer, IConnectionState connectionState)
        {
            var listLength = buffer.ReadBigEndian<ushort>();
            ReadableBuffer signatureAlgoBuffer = default(ReadableBuffer);
            buffer = buffer.Slice(sizeof(ushort));
            if (buffer.Length < listLength)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "The extension list is not as long as the header says");
            }
            var currentbuffer = buffer.Slice(0, listLength);
            buffer = buffer.Slice(currentbuffer.End);
            while (currentbuffer.Length > 3)
            {
                var extensionType = currentbuffer.ReadBigEndian<ExtensionType>();
                var extensionLength = currentbuffer.Slice(sizeof(ExtensionType)).ReadBigEndian<ushort>();
                currentbuffer = currentbuffer.Slice(sizeof(ExtensionType) + sizeof(ushort));
                if (currentbuffer.Length < extensionLength)
                {
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, $"The extension of type {extensionType} is too long for the remaining buffer");
                }
                var extensionBuffer = currentbuffer.Slice(0, extensionLength);
                currentbuffer = currentbuffer.Slice(extensionLength);
                switch (extensionType)
                {
                    case ExtensionType.server_name:
                        ReadServerName(extensionBuffer, connectionState);
                        break;
                    //case ExtensionType.signature_algorithms:
                    //    signatureAlgoBuffer = extensionBuffer;
                    //    break;
                    case ExtensionType.supported_groups:
                        if(connectionState.CipherSuite.ExchangeType == KeyExchange.KeyExchangeType.Ecdhe)
                        {
                            connectionState.CryptoProvider.GetKeyshareFromNamedGroups(extensionBuffer);
                        }
                        break;
                }
            }
            //Wait until the end to check the signature, here we select the
            //certificate and this could depend on the server name indication
            //as well as the trusted CA roots.
            if (signatureAlgoBuffer.Length != 0)
            {
                ReadSignatureScheme(signatureAlgoBuffer, connectionState);
            }
        }

        private static void ReadEarlyData(ReadableBuffer earlyData, IConnectionStateTls13 connectionState)
        {
            connectionState.EarlyDataSupported = true;
        }

        public static void ReadPskKey(ReadableBuffer pskBuffer, IConnectionStateTls13 connectionState)
        {
            var identities = BufferExtensions.SliceVector<ushort>(ref pskBuffer);
            while (identities.Length > 0)
            {
                var identity = BufferExtensions.SliceVector<ushort>(ref identities);
                long serviceId, keyId;
                identity = identity.SliceBigEndian(out serviceId);
                identity = identity.SliceBigEndian(out keyId);
                int ticketAge;
                identities = identities.SliceBigEndian(out ticketAge);
                if (!connectionState.ResumptionProvider.TryToResume(serviceId, keyId, identity, connectionState))
                {
                    continue;
                }
                if ((connectionState.PskKeyExchangeMode & PskKeyExchangeMode.psk_dhe_ke) == 0)
                {
                    connectionState.KeyShare?.Dispose();
                    connectionState.KeyShare = null;
                }
                return;
            }
        }

        public static void ReadPskKeyExchangeMode(ReadableBuffer buffer, IConnectionStateTls13 connectionState)
        {
            buffer = BufferExtensions.SliceVector<byte>(ref buffer);
            while (buffer.Length > 0)
            {
                PskKeyExchangeMode mode;
                buffer = buffer.SliceBigEndian(out mode);
                if (connectionState.PskKeyExchangeMode == PskKeyExchangeMode.none)
                {
                    connectionState.PskKeyExchangeMode = mode;
                }
                else
                {
                    connectionState.PskKeyExchangeMode |= mode;
                }
            }
        }

        public static void ReadApplicationProtocolExtension(ReadableBuffer buffer, IConnectionState connectionState)
        {

        }

        public static TlsVersion ReadSupportedVersion(ReadableBuffer buffer, TlsVersion[] supportedVersions)
        {
            TlsVersion returnVersion = 0;
            buffer = BufferExtensions.SliceVector<byte>(ref buffer);
            while (buffer.Length > 1)
            {
                TlsVersion version;
                buffer = buffer.SliceBigEndian(out version);
                if (supportedVersions.Contains(version))
                {
                    if (version > returnVersion)
                    {
                        returnVersion = version;
                    }
                }
            }
            return returnVersion;
        }

        public static void ReadSupportedGroups(ReadableBuffer buffer, IConnectionStateTls13 connectionState)
        {
            if (connectionState.KeyShare != null)
            {
                return;
            }
            buffer = BufferExtensions.SliceVector<ushort>(ref buffer);
            connectionState.KeyShare = connectionState.CryptoProvider.GetKeyshareFromNamedGroups(buffer);
        }

        public static void ReadKeyshare(ReadableBuffer buffer, IConnectionStateTls13 connectionState)
        {
            if (connectionState.KeyShare?.HasPeerKey == true)
            {
                return;
            }
            buffer = BufferExtensions.SliceVector<ushort>(ref buffer);
            var ks = connectionState.CryptoProvider.GetKeyshareFromKeyshare(buffer);
            connectionState.KeyShare = ks ?? connectionState.KeyShare;
        }

        public static void ReadSignatureScheme(ReadableBuffer buffer, IConnectionState connectionState)
        {
            buffer = BufferExtensions.SliceVector<ushort>(ref buffer);
            while (buffer.Length > 1)
            {
                SignatureScheme scheme;
                buffer = buffer.SliceBigEndian(out scheme);
                var cert = connectionState.CertificateList.GetCertificate(connectionState.ServerName, scheme);
                if (cert != null)
                {
                    connectionState.Certificate = cert;
                    connectionState.SignatureScheme = scheme;
                    return;
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Failed to find a signature scheme that matches");
        }

        public static void ReadServerName(ReadableBuffer buffer, IConnectionState connectionState)
        {
            connectionState.Listener.ServerNameProvider.MatchServerName(buffer, connectionState);
        }
    }
}
