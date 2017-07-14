using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace Leto.Windows.Interop
{
    internal static partial class BCrypt
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        [System.Diagnostics.DebuggerNonUserCode]
        internal static void ThrowOnErrorReturnCode(NTSTATUS returnCode)
        {
            if (returnCode != 0)
            {
                throw new InvalidOperationException($"Api Error {returnCode}");
            }
        }
    }
}
