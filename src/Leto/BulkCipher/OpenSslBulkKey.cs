using System;
using System.Collections.Generic;
using System.Text;
using static Leto.Interop.LibCrypto;

namespace Leto.BulkCipher
{
    public class OpenSslBulkKey : IDisposable
    {
        private EVP_CIPHER_CTX _ctx;
        private Memory<byte> _key;
        private Memory<byte> _iv;
        private EVP_BulkCipher_Type _type;
        private int _tagSize;

        internal OpenSslBulkKey(EVP_BulkCipher_Type type, Memory<byte> key, Memory<byte> iv, int tagSize)
        {
            _tagSize = tagSize;
            _key = key;
            _iv = iv;
            _type = type;
            _ctx = EVP_CIPHER_CTX_new();
        }

        public Memory<byte> Key => _key;
        public Memory<byte> IV => _iv;
        public int TagSize => _tagSize;

        public void Init(KeyMode mode)
        {
            EVP_CipherInit_ex(_ctx, _type, _key.Span, _iv.Span, mode);
        }

        public int Update(Span<byte> input, Span<byte> output)
        {
            return EVP_CipherUpdate(_ctx, output, input);
        }

        public int Update(Span<byte> inputAndOutput)
        {
            return EVP_CipherUpdate(_ctx, inputAndOutput, inputAndOutput);
        }

        public unsafe int AddAdditionalInfo(AdditionalInfo addInfo)
        {
            return EVP_CipherUpdate(_ctx, addInfo);
        }

        public void ReadTag(Span<byte> span)
        {
            if (span.Length < _tagSize)
            {
                throw new ArgumentOutOfRangeException();
            }
            EVP_CIPHER_CTX_GetTag(_ctx, span);
        }

        public void WriteTag(ReadOnlySpan<byte> tagSpan)
        {
            EVP_CIPHER_CTX_SetTag(_ctx, tagSpan);
        }

        public void Finish()
        {
            EVP_CipherFinal_ex(_ctx);
        }

        public void Dispose()
        {
            _ctx.Free();
        }
    }
}
