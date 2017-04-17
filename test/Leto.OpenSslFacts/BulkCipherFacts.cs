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
    public class BulkCipherFacts : IDisposable
    {
        private OpenSslBulkKeyProvider _provider = new OpenSslBulkKeyProvider();

        [Fact]
        public async Task EncryptClientMessageTls12() => await CommonFacts.BulkCipher12Facts.EncryptClientMessage(_provider);

        [Fact]
        public async Task DecryptClientMessageTls12() => await CommonFacts.BulkCipher12Facts.DecryptClientMessage(_provider);

        [Fact]
        public async Task DecryptClientMessageTls13() => await CommonFacts.BulkCipher13Facts.DecryptClientMessage(_provider);

        [Fact]
        public async Task EncryptClientMessageTls13() => await CommonFacts.BulkCipher13Facts.EncryptClientMessage(_provider);

        [Fact]
        public async Task EncryptLargeMessage() => await CommonFacts.BulkCipherLargeDataFacts.EncryptLargeMessage(_provider);

        public void Dispose() => _provider.Dispose();
    }
}
