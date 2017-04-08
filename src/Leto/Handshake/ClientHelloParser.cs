using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using static Leto.BufferExtensions;

namespace Leto.Handshake
{
    public struct ClientHelloParser
    {
        private Span<byte> _clientRandom;
        private TlsVersion _tlsVersion;
        private Span<byte> _sessionId;
        private Span<byte> _cipherSuite;
        private Span<byte> _compressionMethods;
        private List<(ExtensionType, Span<byte>)> _extensions;
        private Span<byte> _originalMessage;

        public ClientHelloParser(ReadableBuffer buffer)
        {
            var span = buffer.ToSpan();
            _originalMessage = span;
            span = span.Slice(Marshal.SizeOf<HandshakeHeader>());
            _tlsVersion = (TlsVersion)ReadBigEndian<ushort>(ref span);
            _clientRandom = ReadFixedVector(ref span, TlsConstants.RandomLength);
            _sessionId = ReadVector8(ref span);
            _cipherSuite = ReadVector16(ref span);
            _compressionMethods = ReadVector8(ref span);
            if (span.Length == 0)
            {
                _extensions = null;
                return;
            }
            _extensions = new List<(ExtensionType, Span<byte>)>();
            var extensionSpan = ReadVector16(ref span);
            if (span.Length > 0)
            {
                ThrowBytesLeftOver();
            }
            while (extensionSpan.Length > 0)
            {
                var type = ReadBigEndian<ExtensionType>(ref extensionSpan);
                var extSpan = ReadVector16(ref extensionSpan);
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
        public List<(ExtensionType, Span<byte>)> Extensions => _extensions;
        public Span<byte> CipherSuites => _cipherSuite;
        public Span<byte> OriginalMessage => _originalMessage;
        public Span<byte> SessionId => _sessionId;
    }
}
