using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public static partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = nameof(BIO_meth_set_ctrl))]
        private static extern int Internal_BIO_meth_set_ctrl(BIO_METHOD biom, ControlDelegate controlMethod);

        internal static void BIO_meth_set_ctrl(BIO_METHOD biom, ControlDelegate controlMethod)
        {
            var result = Internal_BIO_meth_set_ctrl(biom, controlMethod);
            ThrowOnErrorReturnCode(result);
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        internal unsafe delegate long ControlDelegate(BIO bio, BIO_ctrl cmd, long num, void* ptr);
    }
}
