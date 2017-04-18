using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Leto.OpenSsl11;
using Xunit;

namespace Leto.OpenSslFacts
{
    public class RecordLayerFacts
    {
        private OpenSslBulkKeyProvider _provider = new OpenSslBulkKeyProvider();

        [Fact]
        public async Task WriteHandshakeRecord() => await CommonFacts.Tls13RecordHandling.WriteHandshakeRecord(_provider);
    }
}
