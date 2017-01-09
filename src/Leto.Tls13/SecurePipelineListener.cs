using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.State;

namespace Leto.Tls13
{
    public class SecurePipelineListener:IDisposable
    {
        private CryptoProvider _cryptoProvider;
        private PipelineFactory _factory;
        private CertificateList _certificateList;
        private KeyScheduleProvider _keyscheduleProvider;

        public SecurePipelineListener(PipelineFactory factory, CertificateList certificateList)
        {
            _factory = factory;
            _keyscheduleProvider = new KeyScheduleProvider();
            _cryptoProvider = new CryptoProvider();
            _certificateList = certificateList;
        }
        
        public CertificateList CertificateList => _certificateList;
        public CryptoProvider CryptoProvider => _cryptoProvider;
        public KeyScheduleProvider KeyScheduleProvider => _keyscheduleProvider;

        public SecurePipelineConnection CreateSecurePipeline(IPipelineConnection pipeline)
        {
            return new SecurePipelineConnection(pipeline, _factory, this);
        }

        public void Dispose()
        {
            _cryptoProvider.Dispose();
        }
    }
}
