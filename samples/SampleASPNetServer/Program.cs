using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Leto.Kestrel12;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging;

namespace SampleASPNetServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args == null || args.Length < 1 || (args[0] != "leto" && args[0] != "sslstream"))
            {
                Console.WriteLine("leto or sslstream is required");
                return;
            }
            var host = new WebHostBuilder()
                .UseKestrel((ops) =>
                {
                    ops.Listen(new IPEndPoint(IPAddress.Any, 443), lOpts =>
                 {
                     if (args[0] == "leto")
                     {
                         lOpts.UseLetoHttps(".\\data\\new.pfx", "Test123t");
                     }
                     else
                     {
                         lOpts.UseHttps(".\\data\\new.pfx", "Test123t");
                     }
                 });
                })
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseStartup<Startup>()
                .Build();
            host.Run();
        }
    }
}