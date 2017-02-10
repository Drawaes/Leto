using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Net.Sockets;
using System.Threading.Tasks;
using Leto.Tls13;
using Microsoft.AspNetCore.Server.Kestrel.Filter;
using Microsoft.AspNetCore.Server.Kestrel.Https.Internal;
using Microsoft.Extensions.Logging;

namespace Leto.Kestrel11
{
    public class LetoConnectionFilter : IConnectionFilter
    {
        private static readonly ClosedStream _closedStream = new ClosedStream();
        private SecurePipelineListener _listener;
        private CertificateList _certificateList;
        private IConnectionFilter _previous;
        private ILoggerFactory _loggerFactory;
        private PipelineFactory _factory;

        public LetoConnectionFilter(LetoConnectionFilterOptions options, IConnectionFilter previous)
            : this(options, previous, loggerFactory: null)
        {
        }

        public LetoConnectionFilter(LetoConnectionFilterOptions options, IConnectionFilter previous, ILoggerFactory loggerFactory)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }
            if (previous == null)
            {
                throw new ArgumentNullException(nameof(previous));
            }
            _factory = new PipelineFactory();
            _certificateList = new CertificateList();
            var prov = new Tls13.Certificates.OpenSsl11.CertificateProvider();
            _certificateList.AddCertificate(prov.LoadPfx12(options.PfxPath, options.PfxPassword));
            _listener = new SecurePipelineListener(_factory,_certificateList, loggerFactory);
            _previous = previous;
            _loggerFactory = loggerFactory;
        }

        public async Task OnConnectionAsync(ConnectionFilterContext context)
        {
            await _previous.OnConnectionAsync(context);
            if (string.Equals(context.Address.Scheme, "https", StringComparison.OrdinalIgnoreCase))
            {
                var connection = new StreamPipelineConnection(_factory ,context.Connection);
                var secure = _listener.CreateSecurePipeline(connection);
                await secure.HandshakeComplete;
                context.Connection = secure.GetStream();
            }


        }
    }
}
