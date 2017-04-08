using Leto.Hashes;
using System;
using System.Binary;
using System.IO.Pipelines;
using System.Runtime.InteropServices;

namespace Leto.Handshake
{
    public static class HandshakeFraming
    {
        public static readonly int HeaderSize = Marshal.SizeOf<HandshakeHeader>();

        public static bool ReadHandshakeFrame(ref ReadableBuffer buffer, out ReadableBuffer handshakeMessage, out HandshakeType handshakeType)
        {
            if(buffer.Length < HeaderSize)
            {
                handshakeMessage = default(ReadableBuffer);
                handshakeType = HandshakeType.none;
                return false;
            }
            var header = buffer.Slice(0, HeaderSize).ToSpan().Read<HandshakeHeader>();
            if(buffer.Length < (header.Length + HeaderSize))
            {
                handshakeMessage = default(ReadableBuffer);
                handshakeType = HandshakeType.none;
                return false;
            }
            handshakeMessage = buffer.Slice(0, HeaderSize + (int)header.Length);
            buffer = buffer.Slice((int)header.Length + HeaderSize);
            handshakeType = header.MessageType;
            return true;
        }
                
        public static void WriteHandshakeFrame(this ConnectionStates.ConnectionState state, BufferExtensions.ContentWriter content, HandshakeType handshakeType)
        {
            var writer = state.SecureConnection.HandshakeOutput.Writer.Alloc();
            writer.WriteBigEndian(handshakeType);
            BufferExtensions.WriteVector24Bit(ref writer, content);
            if (state.HandshakeHash != null)
            {
                var hashBuffer = writer.AsReadableBuffer();
                state.HandshakeHash.HashData(hashBuffer);
            }
        }
    }
}
