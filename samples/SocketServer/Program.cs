using System;
using System.IO.Pipelines;
using System.Net;
using System.Text;
using System.Buffers;
using System.Runtime;

namespace SocketServer
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine($"Is server GC {GCSettings.IsServerGC}");

            if (args[1] == "s")
            {
                Console.WriteLine("Started SslStream");
                var server = new RawSocketSslStream(args[2]);
                var ignore = server.Run(IPAddress.Parse(args[0]));
                Console.ReadLine();
            }
            if (args[1] == "s2")
            {
                Console.WriteLine("Started SslStream2");
                var server = new RawSocketSslStream2(args[2]);
                var ignore = server.Run(IPAddress.Parse(args[0]));
                Console.ReadLine();
            }
            if (args[1] == "l")
            {
                Console.WriteLine("Started Leto");
                var server = new RawSocketLeto(args[2]);
                server.Run(IPAddress.Parse(args[0])).Wait();
                Console.ReadLine();
            }
            else
            {
                Console.WriteLine("Started no TLS");
                var server = new RawSocketHttpServerSample(args[2]);
                var ignore = server.Run(IPAddress.Parse(args[0]));
                Console.ReadLine();
            }
        }
    }
}
