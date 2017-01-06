using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern unsafe int ECDSA_sign(int type, byte* dgst, int dgstlen, byte* sig, ref int siglen, EC_KEY eckey);
    }
}
