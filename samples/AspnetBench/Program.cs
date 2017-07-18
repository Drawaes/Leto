using System;
using System.IO;
using System.Net;
using System.Runtime;
using System.Threading;
using Leto.KestrelAdapter;
using Microsoft.AspNetCore.Hosting;

namespace AspnetBench
{
    class Program
    {
        static void Main(string[] args)
        {
            PlaintextMiddleware._helloWorldPayload = File.ReadAllBytes(args[0]);
            var webHostBuilder = new WebHostBuilder()
                .UseStartup<Startup>();

            var threads = Environment.ProcessorCount;
            webHostBuilder = webHostBuilder.UseKestrel(options =>
            {
                options.Listen(IPAddress.Parse("127.0.0.1"), 27777, ops =>
                {
                    ops.UseLetoHttps("C:\\code\\TLSCerts\\server.pfx", "test");
                });
            });
            webHostBuilder = webHostBuilder.UseLibuv(options =>
            {
                options.ThreadCount = threads;
            });
            var webhost = webHostBuilder.Build();

            Console.WriteLine($"Using server Kestrel");
            Console.WriteLine($"Server GC is currently {(GCSettings.IsServerGC ? "ENABLED" : "DISABLED")}");

            StartInteractiveConsoleThread();

            webhost.Run();
        }

        private static void StartInteractiveConsoleThread()
        {
            // Run the interaction on a separate thread as we don't have Console.KeyAvailable on .NET Core so can't
            // do a pre-emptive check before we call Console.ReadKey (which blocks, hard)

            var started = new ManualResetEvent(false);

            var interactiveThread = new Thread(() =>
            {
                Console.WriteLine("Press 'C' to force GC or any other key to display GC stats");
                Console.WriteLine();

                started.Set();

                while (true)
                {
                    var key = Console.ReadKey(intercept: true);

                    if (key.Key == ConsoleKey.C)
                    {
                        Console.WriteLine();
                        Console.Write("Forcing GC...");
                        GC.Collect();
                        GC.WaitForPendingFinalizers();
                        GC.Collect();
                        Console.WriteLine(" done!");
                    }
                    else
                    {
                        Console.WriteLine();
                        Console.WriteLine($"Allocated: {GetAllocatedMemory()}");
                        Console.WriteLine($"Gen 0: {GC.CollectionCount(0)}, Gen 1: {GC.CollectionCount(1)}, Gen 2: {GC.CollectionCount(2)}");
                    }
                }
            })
            {
                IsBackground = true
            };

            interactiveThread.Start();

            started.WaitOne();
        }

        private static string GetAllocatedMemory(bool forceFullCollection = false)
        {
            double bytes = GC.GetTotalMemory(forceFullCollection);

            return $"{((bytes / 1024d) / 1024d).ToString("N2")} MB";
        }
    }
}
