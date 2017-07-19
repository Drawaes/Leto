using System;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using SslStream3.Internal;
using static Leto.Interop.LibCrypto;
using static Leto.Interop.OpenSsl;

namespace SslStream3
{
    public class SslStreamPOC : Stream
    {
        private Stream _innerStream;
        private SSL_CTX _ctx;
        private SslState _state;
        private SslBuffer _inputBuffer;

        public SslStreamPOC(Stream innerStream, SSL_CTX ctx)
        {
            _ctx = ctx;
            _innerStream = innerStream;
        }

        public Guid ConnectionId { get; } = Guid.NewGuid();
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotImplementedException();
        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        public async Task AuthenticateAsServerAsync()
        {

            _state = new SslState(_ctx);

            _inputBuffer = SslBuffer.GetBuffer();
            try
            {
                var bytesRead = await ReadMinBytes(5, _inputBuffer);
                if(bytesRead ==0)
                {
                    throw new System.Net.Sockets.SocketException();
                }

                while (true)
                {
                    using (var outputBuffer = SslBuffer.GetBuffer())
                    {
                        var result = _state.DoHandshake(_inputBuffer, outputBuffer);
                        if (outputBuffer.BytesAvailable > 0)
                        {
                            await _innerStream.WriteAsync(outputBuffer.Array, outputBuffer.StartOfBytes, outputBuffer.BytesAvailable);
                        }
                        switch (result)
                        {
                            case HandshakeState.Failed:
                                throw new NotImplementedException();
                            case HandshakeState.Completed:
                                return;
                            case HandshakeState.Continue:
                                bytesRead = await ReadMinBytes(5, _inputBuffer);
                                if(bytesRead == 0)
                                {
                                    throw new System.Net.ProtocolViolationException();
                                }
                                break;
                        }
                    }
                }
            }
            finally
            {
                if (_inputBuffer.BytesAvailable == 0)
                {
                    _inputBuffer.Dispose();
                    _inputBuffer = null;
                }
            }
        }

        public async override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            using (var output = SslBuffer.GetBuffer())
            {
                while (count > 0)
                {
                    var result = _state.Write(output, buffer, offset, count);
                    offset += result;
                    count -= result;
                    await _innerStream.WriteAsync(output.Array, output.StartOfBytes, output.BytesAvailable);
                    output.Clear();
                }
            }
        }

        public async override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            //go for sync first?
            var bytesRead = _state.Read(buffer, offset, count);
            if (bytesRead > 0) return bytesRead;

            //need to go async, first get a buffer if we don't have one
            var inputBuffer = _inputBuffer ?? SslBuffer.GetBuffer();
            _inputBuffer = null;

            bytesRead = await ReadFrame(inputBuffer);
            if (bytesRead == 0) return 0;

            bytesRead = _state.Read(inputBuffer, buffer, offset, count);

            if (inputBuffer.BytesAvailable > 0)
            {
                _inputBuffer = inputBuffer;
            }
            else
            {
                inputBuffer.Dispose();
            }
            return bytesRead;
        }

        private async Task<int> ReadFrame(SslBuffer inputBuffer)
        {
            if (inputBuffer.BytesAvailable < 5)
            {
                var bytesRead = await ReadMinBytes(5, inputBuffer);
                if (inputBuffer.BytesAvailable == 0 || bytesRead == 0) return 0;
            }
            var bytesToReadFrame = inputBuffer.Array[inputBuffer.StartOfBytes + 4] | (inputBuffer.Array[inputBuffer.StartOfBytes + 3] << 8);
            bytesToReadFrame += 5;

            await ReadMinBytes(bytesToReadFrame, inputBuffer);
            return inputBuffer.BytesAvailable;
        }

        private async Task<int> ReadMinBytes(int size, SslBuffer buffer)
        {
            var totalRead = 0;
            while (buffer.BytesAvailable < size)
            {
                var currentBytes = await _innerStream.ReadAsync(buffer.Array, buffer.StartOfEmptySpace, buffer.FreeSpace);
                if (currentBytes == 0) return totalRead;
                totalRead += currentBytes;
                buffer.AddedBytes(currentBytes);
            }
            return totalRead;
        }

        protected override void Dispose(bool isDisposing)
        {
            _state?.Dispose();
            _innerStream.Dispose();
            base.Dispose(isDisposing);
        }

        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotImplementedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotImplementedException();
        public override void SetLength(long value) => throw new NotImplementedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotImplementedException();

        ~SslStreamPOC() => Dispose();
    }
}
