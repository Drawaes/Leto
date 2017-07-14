using System;
using System.Diagnostics;
using System.Linq;

namespace RawHashFunctions
{
    class Program
    {
        static void Main(string[] args)
        {
            var inputData = Enumerable.Repeat<byte>(7, 8 * 1024).ToArray();
            var output = new byte[256 / 8];

            var inputSpan = new Span<byte>(inputData);
            var outputSpan = new Span<byte>(output);

            var outerLoops = 100000;
            var innerLoops = 20;

            var openSsl = new OpenSsl();
            var sw = new Stopwatch();
            sw.Start();
            for(var i = 0; i < outerLoops;i++)
            {
                openSsl.HashData(inputSpan, outputSpan, innerLoops);
            }
            sw.Stop();
            var totalBytes = inputData.Length * (long)outerLoops * innerLoops;
            var bytesPerSecond = totalBytes / ((double)sw.ElapsedMilliseconds / 1000);
            bytesPerSecond /= (1024.0 * 1024.0);

            Console.WriteLine($"OpenSsl {bytesPerSecond} MB/s");

            GC.Collect();
            var cng = new CNG();
            sw.Start();
            for (var i = 0; i < outerLoops; i++)
            {
                cng.HashData(inputSpan, outputSpan, innerLoops);
            }
            sw.Stop();
            totalBytes = inputData.Length * (long)outerLoops * innerLoops;
            bytesPerSecond = totalBytes / ((double)sw.ElapsedMilliseconds / 1000);
            bytesPerSecond /= (1024.0 * 1024.0);

            Console.WriteLine($"CNG {bytesPerSecond} MB/s");

        }
    }
}
