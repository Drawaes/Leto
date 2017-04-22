using System;
using Xunit;

namespace Leto.EphemeralBufferFacts
{
    public class OutOfMemory
    {
        [Fact]
        public void FailDueToWorkingSetSize()
        {
            Assert.Throws<InvalidOperationException>(() =>
            {
                var pool = EphemeralBuffers.EphemeralBufferPool.CreateBufferPool(10000, 10000, false);
            });
        }
    }
}
