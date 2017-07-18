using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    public partial class LibCrypto
    {
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private unsafe static extern void BIO_set_data(BIO a, IntPtr ptr);

        public static unsafe void BIO_set_data(BIO bio, GCHandle handle)
        {
            BIO_set_data(bio, GCHandle.ToIntPtr(handle));
        }
    }
}
