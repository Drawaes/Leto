using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Windows.Interop
{
    internal static partial class BCrypt
    {
        [DllImport(Libraries.BCrypt, CharSet = CharSet.Unicode)]
        private extern static NTSTATUS BCryptDuplicateHash(SafeBCryptHashHandle hHash, out SafeBCryptHashHandle phNewHash, IntPtr pbHashObject, int cbHashObject, int dwFlags);

        internal static SafeBCryptHashHandle BCryptDuplicateHash(SafeBCryptHashHandle handle)
        {
            var result = BCryptDuplicateHash(handle, out SafeBCryptHashHandle newhandle, IntPtr.Zero, 0, 0);
            ThrowOnErrorReturnCode(result);
            return newhandle;
        }
    }
}
