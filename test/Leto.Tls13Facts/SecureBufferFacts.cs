using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Internal;
using Xunit;

namespace Leto.Tls13Facts
{
    public class SecureBufferFacts
    {
        [Fact]
        public void SecureBufferDisposes()
        {
            using (var pool = new SecureBufferPool(100, 100))
            {

            }
        }
    }
}