using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Leto.Tls13.Certificates;
using Leto.Tls13.Internal;
using Leto.Tls13.Sessions;
using Leto.Tls13.State;
using Microsoft.Extensions.Logging;

namespace Leto.Tls13
{
    public class SecurePipeListener : IDisposable
    {
        private CryptoProvider _cryptoProvider;
        private PipeFactory _factory;
        private CertificateList _certificateList;
        private KeyScheduleProvider _keyscheduleProvider;
        private ResumptionProvider _resumptionProvider;
        private ServerNameProvider _serverNameProvider;
        private ILoggerFactory _logFactory;
        private ILogger<SecurePipeListener> _logger;
        private ILogger<SecurePipelineConnection> _connectionLogger;
        
        public SecurePipeListener(PipeFactory factory, CertificateList certificateList, ILoggerFactory logFactory)
        {
            _logFactory = logFactory;
            _logger = logFactory?.CreateLogger<SecurePipeListener>();
            _connectionLogger = logFactory?.CreateLogger<SecurePipelineConnection>();
            _factory = factory;
            _serverNameProvider = new ServerNameProvider();
            _keyscheduleProvider = new KeyScheduleProvider();
            _cryptoProvider = new CryptoProvider(certificateList);
            _resumptionProvider = new ResumptionProvider(4, _cryptoProvider);
            _certificateList = certificateList;
        }

        public CertificateList CertificateList => _certificateList;
        public CryptoProvider CryptoProvider => _cryptoProvider;
        public KeyScheduleProvider KeyScheduleProvider => _keyscheduleProvider;
        public ResumptionProvider ResumptionProvider => _resumptionProvider;
        public ServerNameProvider ServerNameProvider => _serverNameProvider;
        public Func<X509Certificate2Collection, bool> CertificateValidation { get; set; }

        public SecurePipelineConnection CreateSecurePipeline(IPipeConnection pipeline)
        {
            _logger?.LogTrace("Created new secure server pipeline");
            return new SecurePipelineConnection(pipeline, _factory, this, _connectionLogger);
        }

        public SecurePipelineConnection CreateSecureClientPipeline(IPipeConnection pipeline)
        {
            return new SecurePipelineConnection(pipeline, _factory, this, _connectionLogger);
        }

        public void Dispose()
        {
            _cryptoProvider.Dispose();
        }
    }
}
