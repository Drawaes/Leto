using Leto.BulkCiphers;
using Leto.Internal;
using System;
using System.Buffers;
using System.Buffers.Pools;
using static Leto.OpenSsl11.Interop.LibCrypto;

namespace Leto.OpenSsl11
{
    public sealed class OpenSslBulkCipherKey : IBulkCipherKey
    {
        private EVP_CIPHER_CTX _ctx;
        private readonly Memory<byte> _key;
        private readonly Memory<byte> _iv;
        private readonly EVP_BulkCipher_Type _type;
        private readonly int _tagSize;
        private OwnedMemory<byte> _keyStore;

        internal OpenSslBulkCipherKey(EVP_BulkCipher_Type type, OwnedMemory<byte> keyStore, int keySize, int ivSize, int tagSize)
        {
            _tagSize = tagSize;
            _keyStore = keyStore;
            _key = _keyStore.Memory.Slice(0, keySize);
            _iv = _keyStore.Memory.Slice(keySize, ivSize);
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

        public void AddAdditionalInfo(AdditionalInfo addInfo)
        {
            EVP_CipherUpdate(_ctx, addInfo);
        }

        public void ReadTag(Span<byte> span)
        {
            if (span.Length < _tagSize)
            {
                ExceptionHelper.ThrowException(new ArgumentOutOfRangeException());
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
            if (_keyStore != null)
            {
                _keyStore.Dispose();
                _keyStore = null;
            }
            GC.SuppressFinalize(this);
        }

        ~OpenSslBulkCipherKey()
        {
            Dispose();
        }
    }
}
