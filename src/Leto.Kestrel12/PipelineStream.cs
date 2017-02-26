using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Kestrel12
{
    public class StreamPipeConnection : IPipeConnection
    {
        public StreamPipeConnection(PipeFactory factory, Stream stream)
        {
            Input = factory.CreateReader(stream);
            Output = factory.CreateWriter(stream);
        }

        public IPipeReader Input { get; }

        public IPipeWriter Output { get; }

        public void Dispose()
        {
        }
    }
}
