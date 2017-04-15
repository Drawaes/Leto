using Leto.Handshake;
using System;
using System.Binary;
using Xunit;

namespace Leto.ProtocolFacts
{
    public class HandshakeHeaderFacts
    {
        //[Theory]
        //[InlineData(255U, 0x00, 0x00, 0xFF)]
        //[InlineData(16_711_680U, 0xFF, 0x00, 0x00)]
        //[InlineData(13_417_386U, 0xCC, 0xBB, 0xAA)]
        public void HandshakeHeaderSizeTest(uint length, byte firstByte, byte secondByte, byte thirdByte)
        {
            var span = new Span<byte>(new byte[4]);
            span[0] = (byte)HandshakeType.client_hello;
            span[1] = firstByte;
            span[2] = secondByte;
            span[3] = thirdByte;


            var header = span.Read<HandshakeHeader>();
            Assert.Equal(length, header.Length);
            header.Length = length;
            span.Write(header);
            Assert.Equal(firstByte, span[1]);
            Assert.Equal(secondByte, span[2]);
            Assert.Equal(thirdByte, span[3]);
        }
    }
}
