using Leto.BulkCiphers;
using Leto.OpenSsl11;
using Leto.RecordLayer;
using System;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace Leto.OpenSslFacts
{
    public class BulkCipherFacts
    {
        [Fact]
        public async Task EncryptClientMessage()
        {
            var provider = new OpenSslBulkKeyProvider();
            await CommonFacts.BulkCipher12Facts.EncryptClientMessage(provider);
        }

        [Fact]
        public async Task DecryptClientMessage()
        {
            var provider = new OpenSslBulkKeyProvider();
            await CommonFacts.BulkCipher12Facts.DecryptClientMessage(provider);
        }
    }
}
