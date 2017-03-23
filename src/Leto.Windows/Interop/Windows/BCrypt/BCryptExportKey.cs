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
        private unsafe static extern NTSTATUS BCryptExportKey(SafeBCryptKeyHandle hKey, void* encyrptKey, string blobType, void* pbOutput, int cbOutput, out int pcbResult, int dwFlags);

        internal static unsafe int BCryptExportECKey(SafeBCryptKeyHandle handle,int keyExchangeSize, Span<byte> output)
        {
            var tempArray = new byte[sizeof(long) + keyExchangeSize];
            fixed (void* ptr = tempArray)
            {
                var result = BCryptExportKey(handle, null, KeyBlobType.BCRYPT_ECCPUBLIC_BLOB, ptr, tempArray.Length, out int resultSize, 0);
                ThrowOnErrorReturnCode(result);
                //Curve format type 4 (uncompressed)
                output.Write((byte)4);
                tempArray.Slice(sizeof(long), resultSize - sizeof(long)).CopyTo(output.Slice(1));
                return resultSize + 1;
            }
        }
    }
}
