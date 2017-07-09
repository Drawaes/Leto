using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SocketServer
{
    public class HttpResponseStream<TContext> : Stream
    {
        private readonly static Task<int> _initialCachedTask = Task.FromResult(0);
        private Task<int> _cachedTask = _initialCachedTask;

        private readonly HttpConnection<TContext> _connection;

        public HttpResponseStream(HttpConnection<TContext> connection) => _connection = connection;

        public override bool CanRead => false;

        public override bool CanSeek => false;

        public override bool CanWrite => true;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken token) => _connection.WriteAsync(new Span<byte>(buffer, offset, count));

        public override void Flush()
        {
            // No-op since writes are immediate.
        }

        public override Task FlushAsync(CancellationToken cancellationToken) =>
            // No-op since writes are immediate.
            Task.FromResult(0);
    }
}
