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
        private PipelineFactory _pipeFactory = new PipelineFactory();
        private static readonly ClosedAdaptedConnection _closedAdaptedConnection = new ClosedAdaptedConnection();
        private SecurePipelineListener _listener;
        private CertificateList _certList;

        public LetoConnectionAdapter(LetoConnectionAdapterOptions options)
            :this(options, loggerFactory: null)
        {
        }

        public LetoConnectionAdapter(LetoConnectionAdapterOptions options, ILoggerFactory loggerFactory)
        {
            _certList = new CertificateList();
            var provider = new Tls13.Certificates.OpenSsl11.CertificateProvider();
            _certList.AddCertificate(provider.LoadPfx12(options.PfxPath, options.PfxPassword));
            _listener = new SecurePipelineListener(_pipeFactory, _certList, loggerFactory);
        }
                
        public async Task<IAdaptedConnection> OnConnectionAsync(ConnectionAdapterContext context)
        {
            var netStream = context.ConnectionStream as NetworkStream;
            if(netStream == null)
            {
                return _closedAdaptedConnection;
            }
            var connection = _pipeFactory.CreateConnection(netStream);
            var secureConnection = _listener.CreateSecurePipeline(connection);
            await secureConnection.HandshakeComplete;
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
