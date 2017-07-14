using System;
using System.Collections.Generic;
using System.Text;
using static Leto.Windows.Interop.BCrypt;

namespace RawHashFunctions
{
    public class CNG
    {
        Microsoft.Win32.SafeHandles.SafeBCryptAlgorithmHandle _algo;

        public CNG()
        {
            _algo = BCryptOpenAlgorithmProvider("SHA256");
        }

        public void HashData(Span<byte> input, Span<byte> output, int loops)
        {
            var hash = BCryptCreateHash(_algo);
            for (var i = 0; i < loops; i++)
            {
                BCryptHashData(hash, input);
            }
            BCryptFinishHash(hash, output);
            hash.Close();
        }
    }
}
