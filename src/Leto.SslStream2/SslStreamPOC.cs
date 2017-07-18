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
        private SSL_CTX _ctx;
        private SSL _ssl;
        private ArrayBuffer _inputBuffer;
        private ArrayBuffer _outputBuffer;
        private int _bytesToReadFrame;
        private readonly Guid _connectionId = Guid.NewGuid();


        public SslStreamPOC(Stream innerStream)
        {
            _innerStream = innerStream;
            var handle = GCHandle.Alloc(this, GCHandleType.Normal);

            _readBIO = _inputWrapper.New();
            BIO_set_data(_readBIO, handle);

            _writeBIO = _inputWrapper.New();
            BIO_set_data(_writeBIO, handle);

            _inputBuffer = new ArrayBuffer();
            _outputBuffer = new ArrayBuffer();
        }

        public override bool CanRead => true;
        public Guid ConnectionId => _connectionId;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotImplementedException();
        public override long Position { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        internal ArrayBuffer InputBuffer => _inputBuffer;
        internal ArrayBuffer OutputBuffer => _outputBuffer;

        public async Task AuthenticateAsServerAsync(string fileName, string password)
        {
            SetupContext(fileName);

            _ssl = SSL_new(_ctx);
            SSL_set0_rbio(_ssl, _readBIO);
            SSL_set0_wbio(_ssl, _writeBIO);
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
                        bytesRead = await ReadMinBytes(5);
                        if (bytesRead == 0)
                        {
                            throw new InvalidOperationException();
                        }
                        continue;
                    case SslErrorCodes.SSL_WRITING:
                        continue;
                    case SslErrorCodes.SSL_ASYNC_PAUSED:
                        var want = SSL_want(_ssl);
                        if (want == SslErrorCodes.SSL_READING)
                        {
                            bytesRead = await ReadMinBytes(5);
                            if (bytesRead == 0) throw new InvalidDataException();
                        }
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
            var bytes = SSL_read(_ssl, buffer, offset, length);
            if (bytes < 1)
            {
                if (_bytesToReadFrame == 0 && _inputBuffer.BytesAvailable < 5)
                {
                    await ReadMinBytes(5);
                    if (_inputBuffer.BytesAvailable == 0) return 0;
                }
                if (_bytesToReadFrame == 0)
                {
                    _bytesToReadFrame = _inputBuffer.Array[_inputBuffer.StartOfBytes + 4] | (_inputBuffer.Array[_inputBuffer.StartOfBytes + 3] << 8);
                    _bytesToReadFrame += 5;
                }
                await ReadMinBytes(_bytesToReadFrame);
            }
            return SSL_read(_ssl, buffer, offset, length);
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
            return totalRead;
        }

        private void SetupContext(string fileName)
        {
            var bytes = File.ReadAllBytes(fileName);
            var p12 = d2i_PKCS12(bytes);
            var (key, cert) = PKCS12_parse(p12, "test");
            p12.Free();

            _ctx = SSL_CTX_new(TLS_server_method());
            SSL_CTX_use_PrivateKey(_ctx, key);
            SSL_CTX_use_certificate(_ctx, cert);
        }

        protected override void Dispose(bool disposing)
        {
            _inputBuffer.Dispose();
            _outputBuffer.Dispose();
            _ssl.Free();
            _innerStream.Dispose();
            base.Dispose(disposing);
        }
    }
}
