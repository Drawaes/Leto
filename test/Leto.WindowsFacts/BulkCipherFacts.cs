using Leto.BulkCiphers;
using Leto.RecordLayer;
using Leto.Windows;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Leto.WindowsFacts
{
    public class BulkCipherFacts
    {
        [Fact]
        public async Task EncryptClientMessage()
        {
            var provider = new WindowsBulkKeyProvider();
            await CommonFacts.BulkCipher12Facts.EncryptClientMessage(provider);
        }

        [Fact]
        public async Task DecryptClientMessage()
        {
            var provider = new WindowsBulkKeyProvider();
            await CommonFacts.BulkCipher12Facts.DecryptClientMessage(provider);
        }
    }
}
