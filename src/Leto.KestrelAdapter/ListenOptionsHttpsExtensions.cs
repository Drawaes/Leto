using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Leto.KestrelAdapter
{
    /// <summary>
    /// Extension methods fro <see cref="ListenOptions"/> that configure Kestrel to use HTTPS for a given endpoint.
    /// </summary>
    public static class ListenOptionsHttpsExtensions
    {
        /// <summary>
        /// Configure Kestrel to use HTTPS.
        /// </summary>
        /// <param name="listenOptions">
        /// The <see cref="ListenOptions"/> to configure.
        /// </param>
        /// <param name="serverCertificate">
        /// The X.509 certificate.
        /// </param>
        /// <returns>
        /// The <see cref="ListenOptions"/>.
        /// </returns>
        public static ListenOptions UseLetoHttps(this ListenOptions listenOptions, string serverCertificate, string password)
        {
            return listenOptions.UseLetoHttps(new HttpsConnectionAdapterOptions { ServerCertificate = serverCertificate, Password = password });
        }

        /// <summary>
        /// Configure Kestrel to use HTTPS.
        /// </summary>
        /// <param name="listenOptions">
        /// The <see cref="ListenOptions"/> to configure.
        /// </param>
        /// <param name="httpsOptions">
        /// Options to configure HTTPS.
        /// </param>
        /// <returns>
        /// The <see cref="ListenOptions"/>.
        /// </returns>
        public static ListenOptions UseLetoHttps(this ListenOptions listenOptions, HttpsConnectionAdapterOptions httpsOptions)
        {
            var loggerFactory = listenOptions.KestrelServerOptions.ApplicationServices.GetRequiredService<ILoggerFactory>();
            listenOptions.ConnectionAdapters.Add(new HttpsConnectionAdapter(httpsOptions, loggerFactory));
            return listenOptions;
        }
    }
}
