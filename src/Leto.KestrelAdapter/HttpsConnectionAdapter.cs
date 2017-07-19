using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core.Adapter.Internal;
using Microsoft.Extensions.Logging;
using SslStream3;

namespace Leto.KestrelAdapter
{
    public class HttpsConnectionAdapter : IConnectionAdapter
    {
        private static readonly ClosedAdaptedConnection _closedAdaptedConnection = new ClosedAdaptedConnection();

        private readonly HttpsConnectionAdapterOptions _options;
        private readonly ILogger _logger;
        private readonly SslStream3Factory _factory;

        public HttpsConnectionAdapter(HttpsConnectionAdapterOptions options)
            : this(options, loggerFactory: null) => _factory = new SslStream3Factory(_options.ServerCertificate, _options.Password);

        public HttpsConnectionAdapter(HttpsConnectionAdapterOptions options, ILoggerFactory loggerFactory)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (options.ServerCertificate == null)
            {
                throw new ArgumentException("The server certificate parameter is required.", nameof(options));
            }

            _options = options;
            _logger = loggerFactory?.CreateLogger(nameof(HttpsConnectionAdapter));
        }

        public bool IsHttps => true;

        public async Task<IAdaptedConnection> OnConnectionAsync(ConnectionAdapterContext context)
        { 
            var sslStream = _factory.GetStream(context.ConnectionStream);

            try
            {
                await sslStream.AuthenticateAsServerAsync();
            }
            catch (IOException ex)
            {
                _logger?.LogInformation(1, ex, "Failed to authenticate HTTPS connection.");
                sslStream.Dispose();
                return _closedAdaptedConnection;
            }

            // Always set the feature even though the cert might be null
            context.Features.Set<ITlsConnectionFeature>(new TlsConnectionFeature
            {
                ClientCertificate = ConvertToX509Certificate2(null)
            });

            return new HttpsAdaptedConnection(sslStream);
        }

        private static X509Certificate2 ConvertToX509Certificate2(X509Certificate certificate)
        {
            if (certificate == null)
            {
                return null;
            }

            if (certificate is X509Certificate2 cert2)
            {
                return cert2;
            }

            return new X509Certificate2(certificate);
        }

        private class HttpsAdaptedConnection : IAdaptedConnection
        {
            private readonly SslStreamPOC _sslStream;

            public HttpsAdaptedConnection(SslStreamPOC sslStream) => _sslStream = sslStream;

            public Stream ConnectionStream => _sslStream;

            public void Dispose() => _sslStream.Dispose();
        }

        private class ClosedAdaptedConnection : IAdaptedConnection
        {
            public Stream ConnectionStream { get; } = new ClosedStream();

            public void Dispose()
            {
            }
        }
    }
}
