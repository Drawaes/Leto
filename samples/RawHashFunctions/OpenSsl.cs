using System;
using System.Collections.Generic;
using System.Text;
using static Leto.OpenSsl11.Interop.LibCrypto;

namespace RawHashFunctions
{
    public class OpenSsl
    {
        public void HashData(Span<byte> dataToHash, Span<byte> output, int loops)
        {
            var ctx = EVP_MD_CTX_new(EVP_sha256);
            for (var i = 0; i < loops; i++)
            {
                EVP_DigestUpdate(ctx, dataToHash);
            }
            EVP_DigestFinal_ex(ctx, output);
            ctx.Free();
        }
    }
}
