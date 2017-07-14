using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Microsoft.Win32.SafeHandles
{
    internal abstract class SafeBCryptHandle : SafeHandle, IDisposable
    {
        protected SafeBCryptHandle()
            : base(IntPtr.Zero, true)

        {
        }

        public sealed override bool IsInvalid => handle == IntPtr.Zero;

        protected abstract override bool ReleaseHandle();
    }
}
