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

        public SecurePipelineListener(PipelineFactory factory)
        {
            _factory = factory;
            _cryptoProvider = new CryptoProvider();
        }
        
        public SecurePipelineConnection CreateSecurePipeline(IPipelineConnection pipeline)
        {
            return new SecurePipelineConnection(pipeline, _factory, _cryptoProvider);
        }

        public void Dispose()
        {
            
        }
    }
}
