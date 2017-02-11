using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Leto.Kestrel11;
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
                    if (args[0] == "leto")
                    {
                        ops.UseLetoHttps(".\\data\\new.pfx", "Test123t");
                    }
                    else
                    {
                        ops.UseHttps(".\\data\\new.pfx", "Test123t");
                    }
                })
                .UseUrls("https://localhost:443")
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseStartup<Startup>()
                .Build();
            host.Run();
        }
    }
}