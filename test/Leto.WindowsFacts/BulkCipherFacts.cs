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
    public class BulkCipherFacts : IDisposable
    {
        private WindowsBulkKeyProvider _provider = new WindowsBulkKeyProvider();

        //[Fact]
        //public async Task DecryptClientMessageTls13() => await CommonFacts.BulkCipher13Facts.DecryptClientMessage(_provider);

        //[Fact]
        //public async Task EncryptClientMessageTls12() => await CommonFacts.BulkCipher12Facts.EncryptClientMessage(_provider);

        //[Fact]
        //public async Task DecryptClientMessageTls12() => await CommonFacts.BulkCipher12Facts.DecryptClientMessage(_provider);
        
        public void Dispose() => _provider.Dispose();
    }
}
