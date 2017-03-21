using Leto.ConnectionStates;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using static Leto.BufferExtensions;
using static Leto.TlsConstants;
namespace Leto.Handshake
{
    public static class ServerHelloWriter
    {
        public static WritableBuffer Write(WritableBuffer writer, Server12ConnectionState state)
        {
            var fixedSize = RandomLength + sizeof(TlsVersion) + 2 * sizeof(byte) + sizeof(ushort);
            writer.Ensure(fixedSize);
            var span = writer.Buffer.Span;
            span = span.WriteBigEndian(TlsVersion.Tls12);
            state.SecretSchedule.ServerRandom.CopyTo(span);
            span = span.Slice(state.SecretSchedule.ServerRandom.Length);
            
            //We don't support session id's instead resumption is supported through tickets
            span = span.WriteBigEndian<byte>(0);

            span = span.WriteBigEndian(state.CipherSuite.Code);
            //We don't support compression at the TLS level as it is prone to attacks
            span = span.WriteBigEndian<byte>(0);

            writer.Advance(fixedSize);
            //Completed the fixed section now we write the extensions
            WriteExtensions(ref writer, state);
            return writer;
        }

        public static void WriteExtensions(ref WritableBuffer writer, Server12ConnectionState state)
        {
            if (state.SecureRenegotiationSupported)
            {
                state.SecureConnection.Listener.SecureRenegotiationProvider.WriteExtension(ref writer);
            }
            if (state.NegotiatedAlpn != Extensions.ApplicationLayerProtocolType.None)
            {
                state.SecureConnection.Listener.AlpnProvider.WriteExtension(ref writer, state.NegotiatedAlpn);
            }
        }
    }
}
