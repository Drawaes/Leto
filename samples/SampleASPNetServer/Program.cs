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
            var host = new WebHostBuilder()
                .UseKestrel((ops) =>
                {
                    //ops.UseHttps(".\\data\\new.pfx", "Test123t");
                    ops.UseLetoHttps(".\\data\\new.pfx", "Test123t");
                })
                .UseUrls("https://localhost:443")
                .UseContentRoot(Directory.GetCurrentDirectory())
                .UseStartup<Startup>()
                .Build();
            host.Run();
        }
    }
}