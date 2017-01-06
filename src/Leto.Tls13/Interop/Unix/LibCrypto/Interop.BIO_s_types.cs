using System;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        internal static readonly IntPtr BIO_s_secmem = Internal_BIO_s_secmem();
        internal static readonly IntPtr BIO_s_mem = Internal_BIO_s_mem();

        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "BIO_s_secmem")]
        private static extern IntPtr Internal_BIO_s_secmem();
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint= "BIO_s_mem")]
        private static extern IntPtr Internal_BIO_s_mem();
    }
}
