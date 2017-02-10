using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Kestrel11
{
    internal class StreamPipelineConnection : IPipelineConnection
    {
        public StreamPipelineConnection(PipelineFactory factory, Stream stream)
        {
            Input = factory.CreateReader(stream);
            Output = factory.CreateWriter(stream);
        }

        public IPipelineReader Input { get; }

        public IPipelineWriter Output { get; }

        public void Dispose()
        {
            Input.Complete();
            Output.Complete();
        }
    }
}
