using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public unsafe partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "BIO_meth_set_ctrl")]
        private static extern int Internal_BIO_meth_set_ctrl(BIO_METHOD biom, Control controlMethod);

        internal static void BIO_meth_set_ctrl(BIO_METHOD biom, Control controlMethod)
        {
            var result = Internal_BIO_meth_set_ctrl(biom, controlMethod);
            ThrowOnErrorReturnCode(result);
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal delegate long Control(BIO bio, BIO_ctrl cmd, long num, void* ptr);
    }
}
