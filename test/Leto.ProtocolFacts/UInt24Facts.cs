using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Leto.ProtocolFacts
{
    public class UInt24Facts
    {
        [Theory]
        [InlineData(ushort.MaxValue)]
        [InlineData(ushort.MinValue)]
        [InlineData((ushort)1)]
        public void UshortConvertsForwardAndBack(ushort valueToCheck)
        {
            Internal.UInt24 newValue = valueToCheck;
            var returnValue = (ushort)newValue;
            Assert.Equal(valueToCheck, returnValue);
        }

        [Theory]
        [InlineData(ushort.MaxValue)]
        [InlineData(ushort.MinValue)]
        [InlineData((ushort)1)]
        public void UshortConvertsForwardAndBackToInt(int valueToCheck)
        {
            Internal.UInt24 newValue = (ushort)valueToCheck;
            int returnValue = newValue;
            Assert.Equal(valueToCheck, returnValue);
        }
    }
}
