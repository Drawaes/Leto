using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using Leto.Handshake.Extensions;
using Leto.Internal;
using static Leto.BufferExtensions;

namespace Leto.Handshake
{
    public struct ClientHelloParser
    {
        private Span<byte> _clientRandom;
        private TlsVersion _tlsVersion;
        private Span<byte> _sessionId;
        private BigEndianAdvancingSpan _cipherSuite;
        private Span<byte> _compressionMethods;
        private Span<byte> _originalMessage;
        private ApplicationLayerProtocolType _negotiatedAlpn;
        private string _hostName;
        private BigEndianAdvancingSpan _supportedGroups;
        private BigEndianAdvancingSpan _signatureAlgos;
        private BigEndianAdvancingSpan _sessionTicket;

        public ClientHelloParser(ReadableBuffer buffer, SecurePipeConnection secureConnection)
        {
            _originalMessage = buffer.ToSpan();
            var span = new BigEndianAdvancingSpan(_originalMessage);
            span.Read<HandshakeHeader>();
            _tlsVersion = span.Read<TlsVersion>();
            _clientRandom = span.TakeSlice(TlsConstants.RandomLength).ToSpan();
            _sessionId = span.ReadVector<byte>().ToSpan();
            _cipherSuite = span.ReadVector<ushort>();
            _compressionMethods = span.ReadVector<byte>().ToSpan();

            _negotiatedAlpn = ApplicationLayerProtocolType.None;
            _hostName = null;

            if (span.Length == 0)
            {
                return;
            }

            var extensionSpan = new BigEndianAdvancingSpan(span.ReadVector<ushort>().ToSpan());
            while (extensionSpan.Length > 0)
            {
                var extType = extensionSpan.Read<ExtensionType>();
                var extBuffer = extensionSpan.ReadVector<ushort>();
                switch (extType)
                {
                    case ExtensionType.application_layer_protocol_negotiation:
                        _negotiatedAlpn = secureConnection.Listener.AlpnProvider.ProcessExtension(extBuffer);
                        break;
                    case ExtensionType.server_name:
                        _hostName = secureConnection.Listener.HostNameProvider.ProcessHostNameExtension(extBuffer);
                        break;
                    case ExtensionType.signature_algorithms:
                        _signatureAlgos = extBuffer;
                        break;
                    case ExtensionType.supported_groups:
                        _supportedGroups = extBuffer;
                        break;
                    case ExtensionType.SessionTicket:
                        _sessionTicket = extBuffer;
                        break;
                    case ExtensionType.psk_key_exchange_modes:
                    case ExtensionType.pre_shared_key:
                    case ExtensionType.supported_versions:
                    case ExtensionType.key_share:
                        break;
                }
            }

            if (span.Length > 0)
            {
                ThrowBytesLeftOver();
            }
        }

        private static void ThrowBytesLeftOver() =>
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "Bytes left after the end of the client hello");

        public TlsVersion TlsVersion => _tlsVersion;
        public Span<byte> ClientRandom => _clientRandom;
        public BigEndianAdvancingSpan CipherSuites => _cipherSuite;
        public Span<byte> OriginalMessage => _originalMessage;
        public Span<byte> SessionId => _sessionId;
        public ApplicationLayerProtocolType NegotiatedAlpn => _negotiatedAlpn;
        public string HostName => _hostName;
        public BigEndianAdvancingSpan SupportedGroups => _supportedGroups;
        public BigEndianAdvancingSpan SignatureAlgos => _signatureAlgos;
        public BigEndianAdvancingSpan SessionTicket => _sessionTicket;
    }
}
