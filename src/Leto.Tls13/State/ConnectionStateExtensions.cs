using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Handshake;
using Leto.Tls13.Hash;

namespace Leto.Tls13.State
{
    public static class ConnectionStateExtensions
    {
        public static void WriteHandshake(this IConnectionState state, ref WritableBuffer writer, HandshakeType handshakeType, Func<WritableBuffer, IConnectionState, WritableBuffer> contentWriter)
        {
            var dataWritten = writer.BytesWritten;
            writer.WriteBigEndian(handshakeType);
            BufferExtensions.WriteVector24Bit(ref writer, contentWriter, state);
            if (state.HandshakeHash != null)
            {
                var hashBuffer = writer.AsReadableBuffer().Slice(dataWritten);
                state.HandshakeHash.HashData(hashBuffer);
            }
        }
    }
}
