﻿using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Server.Kestrel;
using Microsoft.AspNetCore.Server.Kestrel.Filter;

namespace Leto.WindowsAuthentication
{
    public static class WindowsAuthenticationExtensions
    {
        public static KestrelServerOptions UseWindowsAuthentication(this KestrelServerOptions options)
        {
            var prevFilter = options.ConnectionFilter ?? new NoOpConnectionFilter();
            options.ConnectionFilter = new AuthenticationConnectionFilter(prevFilter);
            return options;
        }

        public static IApplicationBuilder UseWindowsAuthentication(this IApplicationBuilder self)
        {
            self.UseMiddleware<WindowsAuthenticationMiddleware>();
            return self;
        }
    }
}
