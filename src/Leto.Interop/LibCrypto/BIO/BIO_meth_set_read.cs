using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public unsafe partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "BIO_meth_set_read")]
        private static extern int Internal_BIO_meth_set_read(BIO_METHOD biom, ReadDelegate method);

        public static void BIO_meth_set_read(BIO_METHOD biom, ReadDelegate method)
        {
            var returnCode = Internal_BIO_meth_set_read(biom, method);
            ThrowOnErrorReturnCode(returnCode);
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ReadDelegate(BIO bio, void* buf, int size);
    }
}
