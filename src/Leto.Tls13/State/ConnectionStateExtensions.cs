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
        public static void WriteHandshake(this IConnectionStateTls13 state, ref WritableBuffer writer, HandshakeType handshakeType, Func<WritableBuffer, IConnectionStateTls13, WritableBuffer> contentWriter)
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

        public static void WriteHandshake(this IConnectionStateTls12 state, ref WritableBuffer writer, HandshakeType handshakeType, Func<WritableBuffer, IConnectionStateTls12, WritableBuffer> contentWriter)
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

        public static void StartHandshakeHash(this IConnectionState state, ReadableBuffer readable)
        {
            if (state.HandshakeHash == null)
            {
                var t = typeof(string);
                state.HandshakeHash = state.CryptoProvider.HashProvider.GetHashInstance(state.CipherSuite.HashType);
            }
            state.HandshakeHash.HashData(readable);
        }
    }
}
