using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace Leto.Tls13.Hash
{
    public static class HashExtensions
    {
        public static void HashData(this IHashInstance hash, ReadableBuffer datatToHash)
        {
            foreach (var m in datatToHash)
            {
                hash.HashData(m);
            }
        }

        public unsafe static void InterimHash(this IHashInstance instance, byte[] hash)
        {
            fixed (byte* ptr = hash)
            {
                instance.InterimHash(ptr, hash.Length);
            }
        }

        public static unsafe void HashData(this IHashInstance hash, Memory<byte> dataToHash)
        {
            GCHandle handle;
            var ptr = dataToHash.GetPointer(out handle);
            try
            {
                hash.HashData((byte*)ptr, dataToHash.Length);
            }
            finally
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }
        }

        public static unsafe void HashData(this IHashInstance hash, byte[] data)
        {
            fixed (byte* prt = data)
            {
                hash.HashData(prt, data.Length);
            }
        }
    }
}
