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

        [Fact]
        public void InvalidNumberOfBuffersRequested()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                var pool = EphemeralBuffers.EphemeralBufferPool.CreateBufferPool(100, -1);
            });
        }

        [Fact]
        public void InvalidBufferSizeRequested()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                var pool = EphemeralBuffers.EphemeralBufferPool.CreateBufferPool(0, 100);
            });
        }
    }
}
