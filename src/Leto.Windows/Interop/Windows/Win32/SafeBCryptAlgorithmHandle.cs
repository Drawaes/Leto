using Leto.Windows.Interop;
using System;
using System.Runtime.InteropServices;

using NTSTATUS = Leto.Windows.Interop.BCrypt.NTSTATUS;

namespace Microsoft.Win32.SafeHandles
{
    internal sealed class SafeBCryptAlgorithmHandle : SafeBCryptHandle
    {
        private SafeBCryptAlgorithmHandle()
            : base()
        {
        }

        protected sealed override bool ReleaseHandle()
        {
            NTSTATUS ntStatus = BCrypt.BCryptCloseAlgorithmProvider(handle, 0);
            return ntStatus == NTSTATUS.STATUS_SUCCESS;
        }
    }
}