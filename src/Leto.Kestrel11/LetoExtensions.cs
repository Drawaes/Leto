using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Server.Kestrel;
using Microsoft.AspNetCore.Server.Kestrel.Filter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Leto.Kestrel11
{
    public static class LetoExtensions
    {
        public static KestrelServerOptions UseLetoHttps(this KestrelServerOptions kestrelOptions, string path, string password)
        {
            return UseLetoHttps(kestrelOptions, new LetoConnectionFilterOptions() { PfxPassword = password, PfxPath = path });
        }
        public static KestrelServerOptions UseLetoHttps(this KestrelServerOptions kestrelOptions, LetoConnectionFilterOptions options)
        {
            var prevFilter = kestrelOptions.ConnectionFilter ?? new NoOpConnectionFilter();
            var loggerFactory = kestrelOptions.ApplicationServices.GetRequiredService<ILoggerFactory>();
            var filter = new LetoConnectionFilter(options, prevFilter, loggerFactory);
            kestrelOptions.ConnectionFilter = filter;
            return kestrelOptions;
        }
    }
}
