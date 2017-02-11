using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;

namespace SampleASPNetServer
{
    public class Startup
    {
        public void Configure(IApplicationBuilder app, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(LogLevel.Trace);
            var logger = loggerFactory.CreateLogger("Default");

            app.Run(async context =>
            {
                var connectionFeature = context.Connection;
                logger.LogDebug($"Peer: {connectionFeature.RemoteIpAddress?.ToString()}:{connectionFeature.RemotePort}"
                    + $"{Environment.NewLine}"
                    + $"Sock: {connectionFeature.LocalIpAddress?.ToString()}:{connectionFeature.LocalPort}");

                var response = $"hello, world{Environment.NewLine}";
                context.Response.ContentLength = response.Length;
                context.Response.ContentType = "text/plain";
                await context.Response.WriteAsync(response);
            });
        }
    }
}
