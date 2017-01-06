using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        internal enum RSA_PADDING : int
        {
            RSA_PKCS1_PADDING = 1,
            RSA_NO_PADDING = 3,
            RSA_PKCS1_OAEP_PADDING = 4,
            RSA_PKCS1_PSS_PADDING = 6,
        }
    }
}
