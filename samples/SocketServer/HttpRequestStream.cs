using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SocketServer
{
    public class HttpRequestStream<TContext> : Stream
    {
        private readonly static Task<int> _initialCachedTask = Task.FromResult(0);
        private Task<int> _cachedTask = _initialCachedTask;

        private readonly HttpConnection<TContext> _connection;

        public HttpRequestStream(HttpConnection<TContext> connection) => _connection = connection;

        public override bool CanRead => true;

        public override bool CanSeek => false;

        public override bool CanWrite => false;

        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) =>
            // ValueTask uses .GetAwaiter().GetResult() if necessary
            // https://github.com/dotnet/corefx/blob/f9da3b4af08214764a51b2331f3595ffaf162abe/src/System.Threading.Tasks.Extensions/src/System/Threading/Tasks/ValueTask.cs#L156
            ReadAsync(new ArraySegment<byte>(buffer, offset, count)).Result;

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            var task = ReadAsync(new ArraySegment<byte>(buffer, offset, count));

            if (task.IsCompletedSuccessfully)
            {
                if (_cachedTask.Result != task.Result)
                {
                    // Needs .AsTask to match Stream's Async method return types
                    _cachedTask = task.AsTask();
                }
            }
            else
            {
                // Needs .AsTask to match Stream's Async method return types
                _cachedTask = task.AsTask();
            }

            return _cachedTask;
        }

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override void Flush() => throw new NotSupportedException();

        public override Task FlushAsync(CancellationToken cancellationToken) => throw new NotSupportedException();

        private ValueTask<int> ReadAsync(ArraySegment<byte> buffer) => _connection.Input.ReadAsync(buffer);

        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken) => _connection.Input.CopyToAsync(destination, bufferSize, cancellationToken);

    }
}
