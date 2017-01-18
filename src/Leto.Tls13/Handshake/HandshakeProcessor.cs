using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.State;

namespace Leto.Tls13.Handshake
{
    public class HandshakeProcessor
    {
        public const int HandshakeHeaderSize = 4;
                
        public static bool TryGetFrame(ref ReadableBuffer buffer, out ReadableBuffer messageBuffer, out HandshakeType messageType)
        {
            messageType = HandshakeType.certificate;
            messageBuffer = default(ReadableBuffer);

            if (buffer.Length < 4)
            {
                return false;
            }
            messageType = buffer.ReadBigEndian<HandshakeType>();
            var length = buffer.Slice(sizeof(HandshakeType)).ReadBigEndian24bit();
            if(buffer.Length < (length + 4))
            {
                return false;
            }
            messageBuffer = buffer.Slice(0,HandshakeHeaderSize + length);
            buffer = buffer.Slice(HandshakeHeaderSize + length);
            return true;
        }
    }
}
