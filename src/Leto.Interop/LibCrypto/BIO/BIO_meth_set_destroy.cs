using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public unsafe partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "BIO_meth_set_destroy")]
        private static extern int Internal_BIO_meth_set_destroy(BIO_METHOD biom, DestroyDelegate method);

        public static void BIO_meth_set_destroy(BIO_METHOD biom, DestroyDelegate method)
        {
            var returnCode = Internal_BIO_meth_set_destroy(biom, method);
            ThrowOnErrorReturnCode(returnCode);
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int DestroyDelegate(BIO bio);
    }
}
