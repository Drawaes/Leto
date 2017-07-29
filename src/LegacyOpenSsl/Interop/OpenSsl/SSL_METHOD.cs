using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace LegacyOpenSsl.Interop
{
    public static partial class OpenSsl
    {
        public struct SSL_METHOD
        {
            private IntPtr _pointer;
        }

        [DllImport(Libraries.LibSsl, CallingConvention = CallingConvention.Cdecl)]
        public static extern SSL_METHOD TLSv1_2_server_method();

        [DllImport(Libraries.LibSsl, CallingConvention = CallingConvention.Cdecl)]
        public static extern SSL_METHOD TLS_client_method();
    }
}
