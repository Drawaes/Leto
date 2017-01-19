using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Leto.Tls13.Internal;

namespace Leto.DockerTest
{
    public class Program
    {
        public static void Main(string[] args)
        {
            using (var buffer = new SecureBufferPoolUnix(100, 1000))
            {

            }
        }
    }
}
