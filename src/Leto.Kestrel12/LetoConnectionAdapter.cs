using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;
using Leto.Tls13;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Adapter;
using Microsoft.AspNetCore.Server.Kestrel.Https.Internal;
using Microsoft.Extensions.Logging;

namespace Leto.Kestrel12
{
    public class LetoConnectionAdapter : IConnectionAdapter, IDisposable
    {
        private PipeFactory _pipeFactory = new PipeFactory();
        private static readonly ClosedAdaptedConnection _closedAdaptedConnection = new ClosedAdaptedConnection();
        private SecurePipeListener _listener;
        private CertificateList _certList;
        private ILogger _logger;

        public LetoConnectionAdapter(LetoConnectionAdapterOptions options)
            : this(options, loggerFactory: null)
        {
        }

        public LetoConnectionAdapter(LetoConnectionAdapterOptions options, ILoggerFactory loggerFactory)
        {
            _certList = new CertificateList();
            var provider = new Tls13.Certificates.OpenSsl11.CertificateProvider();
            _certList.AddCertificate(provider.LoadPfx12(options.PfxPath, options.PfxPassword));
            _listener = new SecurePipeListener(_pipeFactory, _certList, loggerFactory);
            _logger = loggerFactory?.CreateLogger<LetoConnectionAdapter>();
        }

        public async Task<IAdaptedConnection> OnConnectionAsync(ConnectionAdapterContext context)
        {
            var connection = new StreamPipeConnection(_pipeFactory, context.ConnectionStream);
            var secureConnection = _listener.CreateSecurePipeline(connection);
            try
            {
                await secureConnection.HandshakeComplete;
            }
            catch(Exception ex)
            {
                _logger?.LogInformation(new EventId(10), ex,"Failed to complete a TLS handshake");
                return new ClosedAdaptedConnection();
            }
            return new TlsAdaptedConnection(secureConnection);
        }

        private class ClosedAdaptedConnection : IAdaptedConnection
        {
            public Stream ConnectionStream { get; } = new ClosedStream();

            public void PrepareRequest(IFeatureCollection requestFeatures)
            {
            }
        }

        public void Dispose()
        {
            _listener.Dispose();
            _certList.Dispose();
        }
    }
}
