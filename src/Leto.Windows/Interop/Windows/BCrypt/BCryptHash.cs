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
        private static unsafe extern NTSTATUS BCryptHash(SafeBCryptAlgorithmHandle hAlgorithm, void* pbSecret, uint cbSecret, void* pbInput, uint cbInput, void* pbOutput, uint cbOutput);
    }
}
