using System;
using System.Collections.Generic;
using System.Text;
using static Leto.Interop.LibCrypto;

namespace Leto.Hash
{
    public sealed class OpenSslHash : IHash
    {
        private HashType _hashType;
        private int _size;
        private EVP_MD_CTX _ctx;

        internal OpenSslHash(EVP_HashType hashTypePointer, int size, HashType hashType)
        {
            _hashType = hashType;
            _ctx = EVP_MD_CTX_new(hashTypePointer);
            _size = size;
        }

        public int HashSize => _size;
        public HashType HashType => _hashType;

        public int FinishHash(Span<byte> output)
        {
            var result = EVP_DigestFinal_ex(_ctx, output);
            Dispose();
            return result;
        }

        public void HashData(ReadOnlySpan<byte> data)
        {
            EVP_DigestUpdate(_ctx, data);
        }

        public int InterimHash(Span<byte> output)
        {
            var ctx = EVP_MD_CTX_copy_ex(_ctx);
            try
            {
                return EVP_DigestFinal_ex(ctx, output);
            }
            finally
            {
                ctx.Free();
            }
        }

        public void Dispose()
        {
            if (_ctx.IsValid())
            {
                _ctx.Free();
            }
            GC.SuppressFinalize(this);
        }

        ~OpenSslHash()
        {
            Dispose();
        }
    }
}
