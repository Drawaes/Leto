using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = nameof(DH_compute_key))]
        private static extern unsafe int Internal_DH_compute_key(void* key, BIGNUM pub_key, DH dh);

        public static unsafe int DH_compute_key(Span<byte> key, BIGNUM pub_key, DH dh)
        {
            fixed(void* ptr = &key.DangerousGetPinnableReference())
            {
                return Internal_DH_compute_key(ptr, pub_key, dh);
            }
        }
    }
}
