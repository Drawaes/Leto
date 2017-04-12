using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.OpenSsl11.Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = nameof(DH_set0_pqg))]
        private static extern int Internal_DH_set0_pqg(DH dh, BIGNUM p, BIGNUM q, BIGNUM g);

        internal static void DH_set0_pqg(DH dh, BIGNUM p, BIGNUM q, BIGNUM g)
        {
            var result = Internal_DH_set0_pqg(dh, p, q,g);
            ThrowOnErrorReturnCode(result);
        }
    }
}
