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
        private static unsafe extern NTSTATUS BCryptCreateHash(SafeBCryptAlgorithmHandle hAlgorithm, out SafeBCryptHashHandle phHash, IntPtr pbHashObject, int cbHashObject, void* pbSecret, int cbSecret, BCryptCreateHashFlags dwFlags);

        internal static unsafe SafeBCryptHashHandle BCryptCreateHash(SafeBCryptAlgorithmHandle handle)
        {
            var result = BCryptCreateHash(handle, out SafeBCryptHashHandle hash, IntPtr.Zero, 0, null, 0, BCryptCreateHashFlags.None);
            ThrowOnErrorReturnCode(result);
            return hash;
        }

        [Flags]
        private enum BCryptCreateHashFlags : int
        {
            None = 0x00000000,
            BCRYPT_HASH_REUSABLE_FLAG = 0x00000020,
        }
    }
}
