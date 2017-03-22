using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Windows.Interop
{
    internal partial class BCrypt
    {
        [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode)]
        private static extern NTSTATUS BCryptCreateHash(SafeBCryptAlgorithmHandle hAlgorithm, out SafeBCryptHashHandle phHash, IntPtr pbHashObject, int cbHashObject, [In, Out] byte[] pbSecret, int cbSecret, BCryptCreateHashFlags dwFlags);

        [Flags]
        internal enum BCryptCreateHashFlags : int
        {
            None = 0x00000000,
            BCRYPT_HASH_REUSABLE_FLAG = 0x00000020,
        }
    }
}
