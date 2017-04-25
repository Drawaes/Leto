using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Leto.WindowsAuthentication
{
    public class WindowsAuthStreamWrapper : Stream
    {
        private readonly Stream _innerStream;
        private WindowsAuthFeature _authFeature;

        public WindowsAuthStreamWrapper(Stream inStream, WindowsAuthFeature authFeature)
        {
            _authFeature = authFeature ?? throw new ArgumentNullException(nameof(authFeature));
            _innerStream = inStream ?? throw new ArgumentNullException(nameof(inStream));
        }

        public override bool CanRead => _innerStream.CanRead;
        public override bool CanSeek => _innerStream.CanSeek;
        public override bool CanWrite => _innerStream.CanWrite;
        public override long Length => _innerStream.Length;
        public override long Position { get => _innerStream.Position; set => _innerStream.Position = value; }
        public IWindowsAuthFeature AuthFeature => _authFeature;

        public override void Flush() => _innerStream.Flush();
        public override int Read(byte[] buffer, int offset, int count) => _innerStream.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => _innerStream.Seek(offset, origin);
        public override void SetLength(long value) => _innerStream.SetLength(value);

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            _innerStream.ReadAsync(buffer, offset, count, cancellationToken);

        public override Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken) =>
            _innerStream.CopyToAsync(destination, bufferSize, cancellationToken);

        public override Task FlushAsync(CancellationToken cancellationToken) =>
            _innerStream.FlushAsync(cancellationToken);

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            _innerStream.WriteAsync(buffer, offset, count, cancellationToken);

        public override void Write(byte[] buffer, int offset, int count) => _innerStream.Write(buffer, offset, count);

        protected override void Dispose(bool disposing)
        {
            _authFeature.Dispose();
            base.Dispose(disposing);
        }

#if NET46
        //Below is taken from the Microsoft connection logger stream
        //https://github.com/aspnet/KestrelHttpServer/blob/88890595d1184630c8f64c45b991e4f0cb850064/src/Microsoft.AspNetCore.Server.Kestrel.Core/Adapter/Internal/LoggingStream.cs#L135-L212
        // The below APM methods call the underlying Read/WriteAsync methods which will still be logged.
        public override IAsyncResult BeginRead(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            var task = ReadAsync(buffer, offset, count, default(CancellationToken), state);
            if (callback != null)
            {
                task.ContinueWith(t => callback.Invoke(t));
            }
            return task;
        }

        public override int EndRead(IAsyncResult asyncResult) => ((Task<int>)asyncResult).GetAwaiter().GetResult();
        
        private Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken, object state)
        {
            var tcs = new TaskCompletionSource<int>(state);
            var task = ReadAsync(buffer, offset, count, cancellationToken);
            task.ContinueWith((task2, state2) =>
            {
                var tcs2 = (TaskCompletionSource<int>)state2;
                if (task2.IsCanceled)
                {
                    tcs2.SetCanceled();
                }
                else if (task2.IsFaulted)
                {
                    tcs2.SetException(task2.Exception);
                }
                else
                {
                    tcs2.SetResult(task2.Result);
                }
            }, tcs, cancellationToken);
            return tcs.Task;
        }

        public override IAsyncResult BeginWrite(byte[] buffer, int offset, int count, AsyncCallback callback, object state)
        {
            var task = WriteAsync(buffer, offset, count, default(CancellationToken), state);
            if (callback != null)
            {
                task.ContinueWith(t => callback.Invoke(t));
            }
            return task;
        }

        public override void EndWrite(IAsyncResult asyncResult) => ((Task<object>)asyncResult).GetAwaiter().GetResult();
        
        private Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken, object state)
        {
            var tcs = new TaskCompletionSource<object>(state);
            var task = WriteAsync(buffer, offset, count, cancellationToken);
            task.ContinueWith((task2, state2) =>
            {
                var tcs2 = (TaskCompletionSource<object>)state2;
                if (task2.IsCanceled)
                {
                    tcs2.SetCanceled();
                }
                else if (task2.IsFaulted)
                {
                    tcs2.SetException(task2.Exception);
                }
                else
                {
                    tcs2.SetResult(null);
                }
            }, tcs, cancellationToken);
            return tcs.Task;
        }
#endif
    }
}
