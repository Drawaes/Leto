using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "BIO_meth_set_write")]
        private static extern int Internal_BIO_meth_set_write(BIO_METHOD biom, WriteDelegate method);

        public static void BIO_meth_set_write(BIO_METHOD biom, WriteDelegate method)
        {
            var returnCode = Internal_BIO_meth_set_write(biom, method);
            ThrowOnErrorReturnCode(returnCode);
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public unsafe delegate int WriteDelegate(BIO bio, void* buf, int num);
    }
}
