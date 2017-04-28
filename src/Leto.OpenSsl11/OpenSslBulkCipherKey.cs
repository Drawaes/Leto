using Leto.BulkCiphers;
using Leto.Internal;
using System;
using System.Buffers;
using static Leto.OpenSsl11.Interop.LibCrypto;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslBulkCipherKey : IBulkCipherKey
    {
        private EVP_CIPHER_CTX _ctx;
        private Buffer<byte> _key;
        private Buffer<byte> _iv;
        private readonly EVP_BulkCipher_Type _type;
        private readonly int _tagSize;
        private OwnedBuffer<byte> _keyStore;

        internal OpenSslBulkCipherKey(EVP_BulkCipher_Type type, OwnedBuffer<byte> keyStore, int keySize, int ivSize, int tagSize)
        {
            _tagSize = tagSize;
            _keyStore = keyStore;
            _key = _keyStore.Buffer.Slice(0, keySize);
            _iv = _keyStore.Buffer.Slice(keySize, ivSize);
            _type = type;
            _ctx = EVP_CIPHER_CTX_new();
        }

        public Buffer<byte> IV => _iv;
        public int TagSize => _tagSize;

        public void Init(KeyMode mode) => EVP_CipherInit_ex(_ctx, _type, _key.Span, _iv.Span, mode);
        public int Update(Span<byte> input, Span<byte> output) => EVP_CipherUpdate(_ctx, output, input);
        public int Update(Span<byte> inputAndOutput) => EVP_CipherUpdate(_ctx, inputAndOutput);
        public void AddAdditionalInfo(ref AdditionalInfo addInfo) => EVP_CipherUpdate(_ctx, ref addInfo);

        public void GetTag(Span<byte> span)
        {
            if (span.Length < _tagSize)
            {
                ExceptionHelper.ThrowException(new ArgumentOutOfRangeException());
            }
            EVP_CIPHER_CTX_GetTag(_ctx, span);
        }

        public void SetTag(ReadOnlySpan<byte> tagSpan) => EVP_CIPHER_CTX_SetTag(_ctx, tagSpan);

        public void Dispose()
        {
            _keyStore.Dispose();
            _ctx.Free();
            GC.SuppressFinalize(this);
        }

        public int Finish(Span<byte> inputAndOutput)
        {
            var bytesWritten = 0;
            if (inputAndOutput.Length > 0)
            {
                bytesWritten = Update(inputAndOutput);
            }
            EVP_CipherFinal_ex(_ctx);
            return bytesWritten;
        }

        public int Finish(Span<byte> input, Span<byte> output)
        {
            var bytesWritten = 0;
            if (input.Length > 0)
            {
                bytesWritten = Update(input, output);
            }
            EVP_CipherFinal_ex(_ctx);
            return bytesWritten;
        }

        ~OpenSslBulkCipherKey() => Dispose();
    }
}
