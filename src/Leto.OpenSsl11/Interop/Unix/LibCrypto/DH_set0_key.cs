using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.OpenSsl11.Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = nameof(DH_set0_key))]
        private static extern int Internal_DH_set0_key(DH dh, BIGNUM pub_key, BIGNUM priv_key);

        internal static void DH_set0_key(DH dh, BIGNUM pub_key, BIGNUM priv_key)
        {
            var result = Internal_DH_set0_key(dh, pub_key, priv_key);
            ThrowOnErrorReturnCode(result);
        }
    }
}
