using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using static Leto.Interop.LibCrypto;
using static Leto.Interop.OpenSsl;

namespace SslStream3.Internal
{
    public class SslState : IDisposable
    {
        private static CustomInputBio _customBio = new CustomInputBio();

        private SSL _ssl;
        private BIO _inputBio;
        private BIO _outputBio;

        public SslState(SSL_CTX ctx)
        {
            _inputBio = _customBio.New();
            _outputBio = _customBio.New();
            _ssl = SSL_new(ctx);
            SSL_set0_rbio(_ssl, _inputBio);
            SSL_set0_wbio(_ssl, _outputBio);
            SSL_set_accept_state(_ssl);
        }

        public void Dispose() => _ssl.Dispose();

        public int Read(byte[] buffer, int offset, int length)
        {
            if (SSL_pending(_ssl) <= 0)
            {
                return 0;
            }
            var span = new Span<byte>(buffer, offset, length);
            return SSL_read(_ssl, span);
        }

        public int Write(SslBuffer output, byte[] buffer, int offset, int length)
        {
            var oHandle = GCHandle.Alloc(output, GCHandleType.Normal);
            try
            {
                BIO_set_data(_outputBio, oHandle);
                var span = new Span<byte>(buffer, offset, length);
                return SSL_write(_ssl, span);
            }
            finally
            {
                BIO_reset_data(_outputBio);
                oHandle.Free();
            }
        }

        public int Read(SslBuffer inputBuffer, byte[] buffer, int offset, int length)
        {
            var iHandle = GCHandle.Alloc(inputBuffer, GCHandleType.Normal);
            try
            {
                BIO_set_data(_inputBio, iHandle);
                var span = new Span<byte>(buffer, offset, length);
                return SSL_read(_ssl, span);
            }
            finally
            {
                BIO_reset_data(_inputBio);
                iHandle.Free();
            }
        }

        public HandshakeState DoHandshake(SslBuffer inputBuffer, SslBuffer outputBuffer)
        {
            var iHandle = GCHandle.Alloc(inputBuffer, GCHandleType.Normal);
            var oHandle = GCHandle.Alloc(outputBuffer, GCHandleType.Normal);
            try
            {
                BIO_set_data(_inputBio, iHandle);
                BIO_set_data(_outputBio, oHandle);
                var result = SSL_do_handshake(_ssl);
                
                if(result == 1)
                {
                    return HandshakeState.Completed;
                }
                var errorCode = SSL_get_error(_ssl, result);
                switch (errorCode)
                {
                    case SslErrorCodes.SSL_READING:
                    case SslErrorCodes.SSL_WRITING:
                    case SslErrorCodes.SSL_ASYNC_PAUSED:
                        return HandshakeState.Continue;
                    default:
                        return HandshakeState.Failed;
                }
            }
            finally
            {
                BIO_reset_data(_inputBio);
                BIO_reset_data(_outputBio);
                iHandle.Free();
                oHandle.Free();
            }
        }
    }
}
