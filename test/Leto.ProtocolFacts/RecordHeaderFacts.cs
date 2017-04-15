using Leto.RecordLayer;
using System;
using System.Binary;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Leto.ProtocolFacts
{
    public class RecordHeaderFacts
    {
        [Theory]
        [InlineData(65_280U, 0xFF, 0x00)]
        [InlineData(255U, 0x00, 0xFF)]
        [InlineData(4080U, 0x0F, 0xF0)]
        public void RecordHeaderSizeTests(ushort length, byte firstByte, byte secondByte)
        {
            var span = new Span<byte>(new byte[5]);
            span[0] = (byte)RecordType.Application;
            span[3] = firstByte;
            span[4] = secondByte;
            
            var header = span.Read<RecordHeader>();
            Assert.Equal(length, header.Length);
            header.Length = length;
            span.Write(header);
            Assert.Equal(firstByte, span[3]);
            Assert.Equal(secondByte, span[4]);
        }

    }
}
