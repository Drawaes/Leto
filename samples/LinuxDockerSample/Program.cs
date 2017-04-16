using System;
using System.Runtime.InteropServices;

namespace LinuxDockerSample
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("BlaBla");
           var pool = Leto.EphemeralBuffers.EphemeralBufferPool.CreateBufferPool(1000, 1000);
        }
    }
}