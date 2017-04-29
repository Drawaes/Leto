using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Text;
using Leto.Internal;
using static Leto.BufferExtensions;

namespace Leto.Handshake.Extensions
{
    public class ApplicationLayerProtocolProvider
    {
        //https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids
        private readonly static (ApplicationLayerProtocolType, byte[])[] _protocols = new(ApplicationLayerProtocolType, byte[])[]
        {
            (ApplicationLayerProtocolType.Http1_1, Encoding.ASCII.GetBytes("http/1.1")),
            (ApplicationLayerProtocolType.Spdy1, Encoding.ASCII.GetBytes("spdy/1")),
            (ApplicationLayerProtocolType.Spdy2, Encoding.ASCII.GetBytes("spdy/2")),
            (ApplicationLayerProtocolType.Spdy3, Encoding.ASCII.GetBytes("spdy/3")),
            (ApplicationLayerProtocolType.Turn, Encoding.ASCII.GetBytes("stun.turn")),
            (ApplicationLayerProtocolType.Stun, Encoding.ASCII.GetBytes("stun.nat-discovery")),
            (ApplicationLayerProtocolType.Http2_Tls, Encoding.ASCII.GetBytes("h2")),
            (ApplicationLayerProtocolType.Http2_Tcp, Encoding.ASCII.GetBytes("h2c")),
            (ApplicationLayerProtocolType.WebRtc, Encoding.ASCII.GetBytes("webrtc")),
            (ApplicationLayerProtocolType.Confidential_WebRtc, Encoding.ASCII.GetBytes("c-webrtc")),
            (ApplicationLayerProtocolType.Ftp, Encoding.ASCII.GetBytes("ftp"))
        };

        private (ApplicationLayerProtocolType, byte[])[] _supportedProtocols;
        private bool _serverListTakesPriority;

        public ApplicationLayerProtocolProvider(bool serverListTakesPriority, params ApplicationLayerProtocolType[] supportedProtocols)
        {
            _serverListTakesPriority = serverListTakesPriority;
            if (supportedProtocols?.Length > 0)
            {
                _supportedProtocols = new(ApplicationLayerProtocolType, byte[])[supportedProtocols.Length];
                for (var i = 0; i < _supportedProtocols.Length; i++)
                {
                    _supportedProtocols[i] = _protocols.First((protoType) => protoType.Item1 == supportedProtocols[i]);
                }
            }
            else
            {
                _supportedProtocols = new(ApplicationLayerProtocolType, byte[])[0];
            }
        }

        public void WriteExtension(ref WritableBuffer writer, ApplicationLayerProtocolType negotiatedAlpn)
        {
            var buffer = GetBufferForProtocol(negotiatedAlpn);
            writer.WriteBigEndian(ExtensionType.application_layer_protocol_negotiation);
            writer.WriteBigEndian((byte)(buffer.Length + 1));
            writer.WriteBigEndian((byte)buffer.Length);
            writer.Write(buffer);
        }

        private Span<byte> GetBufferForProtocol(ApplicationLayerProtocolType protocolType)
        {
            foreach (var (proto, buffer) in _supportedProtocols)
            {
                if (proto == protocolType)
                {
                    return buffer;
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "Unknown protocol type negotiated");
            return null;
        }

        public ApplicationLayerProtocolType ProcessExtension(BigEndianAdvancingSpan span)
        {
            if (_serverListTakesPriority)
            {
                return ProcessExtensionServerOrder(span);
            }
            else
            {
                return ProcessExtensionClientOrder(span);
            }
        }

        private ApplicationLayerProtocolType ProcessExtensionServerOrder(BigEndianAdvancingSpan span)
        {
            var originalSpan = span.ToSpan();
            span = span.ReadVector<ushort>();
            foreach (var (alpn, buffer) in _supportedProtocols)
            {
                var loopSpan = span;
                while (loopSpan.Length > 0)
                {
                    var protocol = loopSpan.ReadVector<byte>();
                    if (protocol.ToSpan().SequenceEqual(buffer))
                    {
                        return alpn;
                    }
                }
            }
            Alerts.AlertException.ThrowApplicationProtocol(originalSpan.ToArray());
            return ApplicationLayerProtocolType.None;
        }

        private ApplicationLayerProtocolType ProcessExtensionClientOrder(BigEndianAdvancingSpan span)
        {
            span = span.ReadVector<ushort>();
            while (span.Length > 0)
            {
                var protocol = span.ReadVector<byte>().ToSpan();
                foreach (var (alpn, buffer) in _supportedProtocols)
                {
                    if (protocol.SequenceEqual(buffer))
                    {
                        return alpn;
                    }
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error, "Unable to negotiate a protocol");
            return ApplicationLayerProtocolType.None;
        }
    }
}
