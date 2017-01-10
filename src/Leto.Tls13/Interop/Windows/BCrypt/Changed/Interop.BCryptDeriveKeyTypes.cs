using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

internal partial class Interop
{
    internal partial class BCrypt
    {
		internal const string BCRYPT_KDF_HASH = "HASH";
		internal const string BCRYPT_KDF_HMAC = "HMAC";
		internal const string BCRYPT_KDF_TLS_PRF = "TLS_PRF";
    }
}
