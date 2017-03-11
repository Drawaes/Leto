using System;
using System.Buffers;
using System.Buffers.Pools;
using System.Collections.Generic;
using System.Text;
using static Leto.Interop.LibCrypto;

namespace Leto.BulkCipher
{
    public sealed class OpenSslBulkKey : IDisposable
    {
        private EVP_CIPHER_CTX _ctx;
        private Memory<byte> _key;
        private Memory<byte> _iv;
        private EVP_BulkCipher_Type _type;
        private int _tagSize;
        private BufferPool _bufferPool;
        private OwnedMemory<byte> _keyStore;

        internal OpenSslBulkKey(EVP_BulkCipher_Type type, BufferPool bufferPool, int keySize, int ivSize, int tagSize)
        {
            _tagSize = tagSize;
            _bufferPool = bufferPool;
            _keyStore = bufferPool.Rent(keySize + ivSize);
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
            if (_ctx.IsValid())
            {
                _ctx.Free();
            }
            if (_keyStore != null)
            {
                _bufferPool.Return(_keyStore);
                _keyStore = null;
            }
            GC.SuppressFinalize(this);
        }

        ~OpenSslBulkKey()
        {
            Dispose();
        }
    }
}
