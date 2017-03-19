using Leto.Hashes;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using System.Text;

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

        public static void WriteHandshakeFrame(ref WritableBuffer writer, IHash handshakeHash,
            Func<WritableBuffer, WritableBuffer> contentWriter, HandshakeType handshakeType)
        {
            var dataWritten = writer.BytesWritten;
            writer.WriteBigEndian(handshakeType);
            BufferExtensions.WriteVector24Bit(ref writer, contentWriter);
            if (handshakeHash != null)
            {
                var hashBuffer = writer.AsReadableBuffer().Slice(dataWritten);
                handshakeHash.HashData(hashBuffer);
            }
        }
    }
}
