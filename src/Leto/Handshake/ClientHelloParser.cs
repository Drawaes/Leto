using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;

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

        public ClientHelloParser(ReadableBuffer buffer)
        {
            var span = new BigEndianSpanReader(buffer.ToSpan());
            _tlsVersion = (TlsVersion) span.Read<ushort>();
            _clientRandom = span.ReadFixed(32);
            _sessionId = span.ReadVector8();
            _cipherSuite = span.ReadVector16();
            _compressionMethods = span.ReadVector8();
            if (span.Length == 0)
            {
                _extensions = null;
                return;
            }
            _extensions = new List<(ExtensionType, Span<byte>)>();
            var extensionSpan = new BigEndianSpanReader(span.ReadVector16());
            if(span.Length > 0)
            {
                ThrowBytesLeftOver();
            }
            while(extensionSpan.Length > 0)
            {
                var type = (ExtensionType)extensionSpan.Read<ushort>();
                var extSpan = extensionSpan.ReadVector16();
                _extensions.Add((type, extSpan));
            }
        }

        private static void ThrowBytesLeftOver()
        {
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "Bytes left after the end of the client hello");
        }

        public TlsVersion TlsVersion => _tlsVersion;
        public Span<byte> ClientRandom => _clientRandom;
    }
}
