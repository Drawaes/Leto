using System;
using System.Buffers;
using System.IO;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using static Leto.Interop.LibCrypto;
using static Leto.Interop.OpenSsl;

namespace Leto.SslStream2
{
    public class SslStreamPOC : Stream
    {
        private static readonly CustomInputBio _inputWrapper = new CustomInputBio();
        private BIO _readBIO;
        private BIO _writeBIO;
        private Stream _innerStream;
        private SSL _ssl;
        private ArrayBuffer _inputBuffer;
        private ArrayBuffer _outputBuffer;
        private int _bytesToReadFrame;
        private readonly Guid _connectionId = Guid.NewGuid();
        private GCHandle _handle;
       
        internal SslStreamPOC(Stream innerStream, SSL_CTX context)
        {
            _innerStream = innerStream;
            _handle = GCHandle.Alloc(this, GCHandleType.Normal);

            _readBIO = _inputWrapper.New(_handle);
            _writeBIO = _inputWrapper.New(_handle);

            _inputBuffer = new ArrayBuffer();
            _outputBuffer = new ArrayBuffer();

            _ssl = SSL_new(context);
            SSL_set0_rbio(_ssl, _readBIO);
            SSL_set0_wbio(_ssl, _writeBIO);
        }

        public override bool CanRead => true;
        public Guid ConnectionId => _connectionId;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotImplementedException();
        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        internal ArrayBuffer InputBuffer => _inputBuffer;
        internal ArrayBuffer OutputBuffer => _outputBuffer;

        public async Task AuthenticateAsServerAsync()
        {
            SSL_set_accept_state(_ssl);
            if (await ReadMinBytes(5) == 0) throw new InvalidOperationException();

            while (true)
            {
                var result = SSL_do_handshake(_ssl);
                if (_outputBuffer.BytesAvailable > 0)
                {
                    await _innerStream.WriteAsync(_outputBuffer.Array, _outputBuffer.StartOfBytes, _outputBuffer.BytesAvailable);
                    _outputBuffer.Clear();
                }

                if (result == 1)
                {
                    //finished!!
                    return;
                }
                var errorCode = SSL_get_error(_ssl, result);
                var bytesRead = 0;
                switch (errorCode)
                {
                    case SslErrorCodes.SSL_READING:
                    case SslErrorCodes.SSL_WRITING:
                    case SslErrorCodes.SSL_ASYNC_PAUSED:
                        var want = SSL_want(_ssl);
                        if (want == SslErrorCodes.SSL_READING)
                        {
                            bytesRead = await ReadMinBytes(5);
                            if (bytesRead == 0) throw new InvalidDataException();
                        }
                        continue;
                    case SslErrorCodes.SSL_NOTHING:
                        continue;
                    default:
                        throw new NotImplementedException();
                }
            }

        }

        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count) => throw new NotImplementedException();

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int length, System.Threading.CancellationToken token)
        {
            //var bytes = SSL_read(_ssl, buffer, offset, length);
            //if (bytes < 1)
            //{
            //    var error = SSL_get_error(_ssl, bytes);
            //    if (_bytesToReadFrame == 0 && _inputBuffer.BytesAvailable < 5)
            //    {
            //        await ReadMinBytes(5);
            //        if (_inputBuffer.BytesAvailable == 0) return 0;
            //    }
            //    if (_bytesToReadFrame == 0)
            //    {
            //        _bytesToReadFrame = _inputBuffer.Array[_inputBuffer.StartOfBytes + 4] | (_inputBuffer.Array[_inputBuffer.StartOfBytes + 3] << 8);
            //        _bytesToReadFrame += 5;
            //    }
            //    await ReadMinBytes(_bytesToReadFrame);
            //}
            //return SSL_read(_ssl, buffer, offset, length);
            throw new NotImplementedException();
        }

        public override long Seek(long offset, SeekOrigin origin) => throw new NotImplementedException();

        public override void SetLength(long value) => throw new NotImplementedException();

        public override void Write(byte[] buffer, int offset, int count) => throw new NotImplementedException();

        public override async Task WriteAsync(byte[] buffer, int offset, int count, System.Threading.CancellationToken token)
        {
            while (count > 0)
            {
                var result = SSL_write(_ssl, buffer, offset, count);
                offset += result;
                count -= result;
                await _innerStream.WriteAsync(_outputBuffer.Array, _outputBuffer.StartOfBytes, _outputBuffer.BytesAvailable);
                _outputBuffer.Clear();
            }
        }

        private async Task<int> ReadMinBytes(int minRead)
        {
            if (minRead - _inputBuffer.BytesAvailable > _inputBuffer.FreeSpace)
            {
                //move the data to the front of the block
                _inputBuffer.MoveDataToFront();
            }
            var totalRead = 0;
            while (_inputBuffer.BytesAvailable < minRead)
            {
                try
                {
                    var bytesRead = await _innerStream.ReadAsync(_inputBuffer.Array, _inputBuffer.StartOfEmptySpace, _inputBuffer.FreeSpace);
                    if (bytesRead == 0)
                    {
                        //Connection finished need to handle
                        return totalRead;
                    }
                    else
                    {
                        totalRead += bytesRead;
                        _inputBuffer.AddedBytes(bytesRead);
                    }
                }
                catch
                {
                    return totalRead;
                }
            }
            return totalRead;
        }

        protected override void Dispose(bool disposing)
        {
            _ssl?.Dispose();
            
            _inputBuffer?.Dispose();
            _inputBuffer = null;
            _outputBuffer?.Dispose();
            _outputBuffer = null;
            
            if (_handle.IsAllocated)
            {
                _handle.Free();
            }
            _innerStream?.Dispose();
            _innerStream = null;
            base.Dispose(disposing);
        }
    }
}
