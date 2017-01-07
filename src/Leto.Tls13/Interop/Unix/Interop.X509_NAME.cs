using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

internal partial class Interop
{
    internal partial class LibCrypto
    {
        private static readonly string LN_subject_alt_name = "X509v3 Subject Alternative Name";
        private static readonly string LN_commonName = "commonName";
        private static readonly int NID_subject_alt_name = OBJ_ln2nid(LN_subject_alt_name);
        private static readonly int NID_commonname = OBJ_ln2nid(LN_commonName);

        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int X509_NAME_get_index_by_NID(IntPtr name, int nid, int lastpos);
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr X509_NAME_get_entry(IntPtr name, int loc);
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr X509_NAME_ENTRY_get_data(IntPtr ne);
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int ASN1_STRING_to_UTF8(out IntPtr ptr, IntPtr inPtr);
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int X509_get_ext_by_NID(X509 x, int nid, int lastpos);

        internal static unsafe string GetNameString(X509 certificate)
        {
            var name = X509_get_subject_name(certificate);
            var altIndex = X509_NAME_get_index_by_NID(name, NID_subject_alt_name, -1);
            if (altIndex < 0)
            {
                altIndex = X509_NAME_get_index_by_NID(name, NID_commonname, -1);
                if(altIndex < 0)
                {
                    return null;
                }
            }
            var entry = X509_NAME_get_entry(name, altIndex);
            var entryData = X509_NAME_ENTRY_get_data(entry);
            IntPtr buffer;
            var dataLength = ASN1_STRING_to_UTF8(out buffer, entryData);
            try
            {
                return Encoding.UTF8.GetString((byte*)buffer, dataLength);
            }
            finally
            {
                CRYPTO_clear_free(buffer, (UIntPtr)dataLength, "Interop.X509_NAME.cs", 42);
            }
        }
    }
}
