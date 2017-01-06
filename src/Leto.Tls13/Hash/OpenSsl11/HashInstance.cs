using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static Interop.LibCrypto;

namespace Leto.Tls13.Hash.OpenSsl11
{
    public class HashInstance:IHashInstance
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

        public void HashData(ReadableBuffer datatToHash)
        {
            foreach (var m in datatToHash)
            {
                HashData(m);
            }
        }

        public unsafe void HashData(Memory<byte> dataToHash)
        {
            GCHandle handle;
            var ptr = dataToHash.GetPointer(out handle);
            try
            {
                HashData((byte*)ptr, dataToHash.Length);
            }
            finally
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }
        }

        public unsafe void HashData(byte* buffer, int bufferLength)
        {
            ThrowOnError(EVP_DigestUpdate(_ctx, buffer, bufferLength));
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
