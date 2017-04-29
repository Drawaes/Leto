using Leto.OpenSsl11;
using System;
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

        public void Dispose() => _provider.Dispose();
    }
}
