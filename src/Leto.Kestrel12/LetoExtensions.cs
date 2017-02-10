using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Server.Kestrel;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Leto.Kestrel12
{
    public static class LetoExtensions
    {
        public static ListenOptions UseLetoHttps(this ListenOptions options,string path, string password)
        {
            var opts = new LetoConnectionAdapterOptions()
            {
                PfxPassword = password,
                PfxPath = path
            };
            var loggerFactory = options.KestrelServerOptions.ApplicationServices.GetRequiredService<ILoggerFactory>();
            options.ConnectionAdapters.Add(new LetoConnectionAdapter(opts, loggerFactory));
            return options;
        }
    }
}
