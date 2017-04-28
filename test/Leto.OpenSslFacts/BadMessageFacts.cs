using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Leto.OpenSslFacts
{
    public class BadMessageFacts
    {
        [Fact]
        public async Task ClientHelloWithExtraBytes()
        {
            using (var listener = new OpenSsl11.OpenSslSecurePipeListener(Data.Certificates.RSACertificate))
            {
                await CommonFacts.BadHelloFacts.SendHelloWithExtraTrailingBytes(listener);
            }
        }
    }
}
