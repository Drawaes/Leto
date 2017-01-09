using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        internal static readonly IntPtr EVP_sha256 = Internal_EVP_sha256();
        internal static readonly IntPtr EVP_sha384 = Internal_EVP_sha384();
        internal static readonly IntPtr EVP_sha512 = Internal_EVP_sha512();                                                 

        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "EVP_sha256")]
        private static extern IntPtr Internal_EVP_sha256();
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "EVP_sha384")]
        private static extern IntPtr Internal_EVP_sha384();
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl, EntryPoint = "EVP_sha512")]
        private static extern IntPtr Internal_EVP_sha512();
    }
}
