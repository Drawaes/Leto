using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SslStreamVsLeto
{
    public class Program
    {
        public static void Main(string[] args)
        {
            //var crossing = new CrossingTheStreams();
            //CrossingTheStreams.Setup();
            //crossing.Stream2Stream().Wait();
            ////crossing.Stream2Leto().Wait();

            var summary = BenchmarkDotNet.Running.BenchmarkRunner.Run<CrossingTheStreams>();
            Console.ReadLine();
        }
    }
}
