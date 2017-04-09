using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
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
        private List<(ExtensionType, BigEndianAdvancingSpan)> _extensions;
        private Span<byte> _originalMessage;

        public ClientHelloParser(ReadableBuffer buffer)
        {
            _originalMessage = buffer.ToSpan();
            var span = new BigEndianAdvancingSpan(_originalMessage);
            span.Read<HandshakeHeader>();
            _tlsVersion = span.Read<TlsVersion>();
            _clientRandom = span.TakeSlice(TlsConstants.RandomLength).ToSpan();
            _sessionId = span.ReadVector<byte>().ToSpan();
            _cipherSuite = span.ReadVector<ushort>();
            _compressionMethods = span.ReadVector<byte>().ToSpan();
            if (span.Length == 0)
            {
                _extensions = null;
                return;
            }
            _extensions = new List<(ExtensionType, BigEndianAdvancingSpan)>();
            var extensionSpan = span.ReadVector<ushort>();
            if (span.Length > 0)
            {
                ThrowBytesLeftOver();
            }
            while (extensionSpan.Length > 0)
            {
                var type = extensionSpan.Read<ExtensionType>();
                var extSpan = extensionSpan.ReadVector<ushort>();
                if (Enum.IsDefined(typeof(ExtensionType), type))
                {
                    _extensions.Add((type, extSpan));
                }
            }
        }

        private static void ThrowBytesLeftOver() =>
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "Bytes left after the end of the client hello");

        public TlsVersion TlsVersion => _tlsVersion;
        public Span<byte> ClientRandom => _clientRandom;
        public List<(ExtensionType, BigEndianAdvancingSpan)> Extensions => _extensions;
        public BigEndianAdvancingSpan CipherSuites => _cipherSuite;
        public Span<byte> OriginalMessage => _originalMessage;
        public Span<byte> SessionId => _sessionId;
    }
}
