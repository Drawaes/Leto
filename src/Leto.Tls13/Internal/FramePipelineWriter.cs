using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Leto.Tls13.Internal
{
    public class FramePipelineWriter : IPipelineWriter
    {
        private ManualResetEventSlim _finishedWriting;
        private IPipelineWriter _writer;

        public FramePipelineWriter(ManualResetEventSlim finishedWriting, IPipelineWriter writer)
        {
            _finishedWriting = finishedWriting;
            _writer = writer;
        }

        public Task Writing => _writer.Writing;

        public WritableBuffer Alloc(int minimumSize = 0)
        {
             return _writer.Alloc(minimumSize);
        }

        public void Complete(Exception exception = null)
        {
            _writer.Complete(exception);
            _finishedWriting.Wait();
            _finishedWriting.Dispose();
        }
    }
}
