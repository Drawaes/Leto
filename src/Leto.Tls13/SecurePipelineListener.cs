using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13
{
    public class SecurePipelineListener:IDisposable
    {
        private CryptoProvider _cryptoProvider;
        private PipelineFactory _factory;
        private CertificateList _certificateList;

        public SecurePipelineListener(PipelineFactory factory, CertificateList certificateList)
        {
            _factory = factory;
            _cryptoProvider = new CryptoProvider();
            _certificateList = certificateList;
        }
        
        public CertificateList CertificateList => _certificateList;
        public CryptoProvider CryptoProvider => _cryptoProvider;

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
