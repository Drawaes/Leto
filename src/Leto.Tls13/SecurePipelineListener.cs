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

        public SecurePipelineConnection CreateSecurePipeline(IPipelineConnection pipeline)
        {
            return new SecurePipelineConnection(pipeline, _factory, _cryptoProvider, _certificateList);
        }

        public void Dispose()
        {
            
        }
    }
}
