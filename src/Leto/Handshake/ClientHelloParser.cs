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
        private Span<byte> _originalMessage;
        private Span<byte> _extensionSpan;

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
                return;
            }

            _extensionSpan = span.ReadVector<ushort>().ToSpan();
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
        public Span<byte> ExtensionsSpan => _extensionSpan;

    }
}
