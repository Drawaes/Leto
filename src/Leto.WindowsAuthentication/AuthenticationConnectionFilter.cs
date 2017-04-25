﻿using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Server.Kestrel.Filter;

namespace Leto.WindowsAuthentication
{
    public class AuthenticationConnectionFilter : IConnectionFilter
    {
        private IConnectionFilter _previous;

        public AuthenticationConnectionFilter(IConnectionFilter previous) => _previous = previous ?? throw new ArgumentNullException();

        public async Task OnConnectionAsync(ConnectionFilterContext context)
        {
            await _previous.OnConnectionAsync(context);
            var previousRequest = context.PrepareRequest;
            var feature = new WindowsAuthFeature();
            var wrapper = new WindowsAuthStreamWrapper(context.Connection, feature);
            context.Connection = wrapper;
            context.PrepareRequest = features =>
            {
                previousRequest?.Invoke(features);
                features.Set(((WindowsAuthStreamWrapper)context.Connection).AuthFeature);
            };

        }
    }
}
