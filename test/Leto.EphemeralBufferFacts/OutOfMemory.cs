using System;
using Xunit;

namespace Leto.EphemeralBufferFacts
{
    public class OutOfMemory
    {
        [Fact]
        public void FailDueToWorkingSetSize() => Assert.Throws<InvalidOperationException>(() =>
            {
                var pool = EphemeralBuffers.EphemeralBufferPool.CreateBufferPool(10000, 10000, false);
            });

        [Fact]
        public void InvalidNumberOfBuffersRequested() => Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                var pool = EphemeralBuffers.EphemeralBufferPool.CreateBufferPool(100, -1);
            });

        [Fact]
        public void InvalidBufferSizeRequested() => Assert.Throws<ArgumentOutOfRangeException>(() =>
            {
                var pool = EphemeralBuffers.EphemeralBufferPool.CreateBufferPool(0, 100);
            });

        [Fact]
        public void RequestedBufferIsTooLarge()
        {
            using (var pool = EphemeralBuffers.EphemeralBufferPool.CreateBufferPool(64, 100))
            {
                Assert.Throws<InvalidOperationException>(() =>
                {
                    pool.Rent(500);
                });
            }
        }

        [Fact]
        public void RequestedTooManyBuffers()
        {
            using (var pool = EphemeralBuffers.EphemeralBufferPool.CreateBufferPool(512, 8))
            {
                for (var i = 0; i < 8; i++)
                {
                    pool.Rent(512);
                }
                Assert.Throws<InvalidOperationException>(() =>
                {
                    //due to page sizing we might have more buffers than originally requested
                    pool.Rent(512);
                    pool.Rent(512);
                    pool.Rent(512);
                    pool.Rent(512);
                });
            }
        }
    }
}
