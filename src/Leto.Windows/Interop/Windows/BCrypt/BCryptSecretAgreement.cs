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
        private static extern NTSTATUS BCryptSecretAgreement(SafeBCryptKeyHandle hPrivKey, SafeBCryptKeyHandle hPubKey, out SafeBCryptSecretHandle phSecret, int dwFlags);

        internal static SafeBCryptSecretHandle BCryptSecretAgreement(SafeBCryptKeyHandle keyPair, SafeBCryptKeyHandle peerKey)
        {
            var result = BCryptSecretAgreement(keyPair, peerKey, out SafeBCryptSecretHandle handle, 0);
            ThrowOnErrorReturnCode(result);
            return handle;
        }
    }
}
