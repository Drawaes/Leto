using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;

namespace Leto.OpenSslFacts
{
    public class LoopbackPipeline
    {
        IPipeConnection _clientPipeline;
        IPipeConnection _serverPipeline;

        public LoopbackPipeline(PipeFactory factory)
        {
            var backPipeline1 = factory.Create();
            var backPipeline2 = factory.Create();

            _clientPipeline = new TestPipeline(backPipeline1, backPipeline2);
            _serverPipeline = new TestPipeline(backPipeline2, backPipeline1);
        }

        public IPipeConnection ServerPipeline => _serverPipeline;
        public IPipeConnection ClientPipeline => _clientPipeline;

        class TestPipeline : IPipeConnection
        {
            IPipe _inPipeline;
            IPipe _outPipeline;

            public TestPipeline(IPipe inPipeline, IPipe outPipeline)
            {
                _inPipeline = inPipeline;
                _outPipeline = outPipeline;
            }

            public IPipeReader Input => _inPipeline.Reader;
            public IPipeWriter Output => _outPipeline.Writer;
            public void Dispose()
            {
            }
        }
    }
}
