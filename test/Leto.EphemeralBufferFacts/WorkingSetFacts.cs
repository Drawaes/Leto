using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Leto.EphemeralBufferFacts
{
    public class WorkingSetFacts
    {
        [Fact]
        public void FailDueToWorkingSetSize() => Assert.Throws<InvalidOperationException>(() =>
        {
            var pool = EphemeralBuffers.EphemeralBufferPool.CreateBufferPool(10000, 10000, false);
        });

        [Fact]
        public void WorkingSetIncreased()
        {
            var pool = EphemeralBuffers.EphemeralBufferPool.CreateBufferPool(2000, 2000, true);
            Assert.True(pool.WorkingSetIncreased);
        }
    }
}
