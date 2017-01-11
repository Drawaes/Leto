using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static Interop.LibCrypto;

namespace Leto.Tls13.Hash.OpenSsl11
{
    public class HashInstance : IHashInstance
    {
        private EVP_MD_CTX _ctx;
        private int _size;
        private HashType _hashType;

        internal HashInstance(EVP_MD_CTX ctx, int size, HashType hashType)
        {
            _hashType = hashType;
            _ctx = ctx;
            _size = size;
        }

        public int HashSize => _size;
    
        public unsafe void HashData(byte* buffer, int bufferLength)
        {
            ThrowOnError(EVP_DigestUpdate(_ctx, buffer, bufferLength));
        }
        
        public unsafe void InterimHash(byte* buffer, int length)
        {
            var ctx = EVP_MD_CTX_new();
            try
            {
                ThrowOnError(EVP_MD_CTX_copy_ex(ctx, _ctx));
                ThrowOnError(EVP_DigestFinal_ex(ctx, buffer, ref length));
            }
            finally
            {
                ctx.Free();
            }
        }

        public void Dispose()
        {
            _ctx.Free();
            GC.SuppressFinalize(this);
        }
        
        ~HashInstance()
        {
            Dispose();
        }
    }
}
