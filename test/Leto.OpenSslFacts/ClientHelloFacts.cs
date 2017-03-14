using Leto.ConnectionStates;
using Leto.OpenSsl11;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Leto.OpenSslFacts
{
    public class ClientHelloFacts
    {
        [Fact]
        public async Task Tls12ReplacesConnectionStateCorrectly()
        {
            using (var factory = new PipeFactory())
            {
                var pipe = factory.Create();
                var writer = pipe.Writer.Alloc();
                writer.Write(Data.Tls12ClientMessages.ClientHello);
                await writer.FlushAsync();
                var reader = await pipe.Reader.ReadAsync();
                var buffer = reader.Buffer;
                IConnectionState newState = null;
                var state = new ServerUnknownVersionState((connecter) => newState = connecter, new OpenSslCryptoProvider());
                state.HandleHandshakeRecord(ref buffer, ref writer);
                Assert.IsType(typeof(Server12ConnectionState), newState);
            }
        }

        [Fact]
        public async Task Tls12RejectNonClientHelloAsFirstMessage()
        {
            using (var factory = new PipeFactory())
            {
                var pipe = factory.Create();
                var writer = pipe.Writer.Alloc();
                writer.Write(Data.Tls12ClientMessages.ClientKeyExchange);
                await writer.FlushAsync();
                var reader = await pipe.Reader.ReadAsync();
                var buffer = reader.Buffer;
                IConnectionState newState = null;
                var state = new ServerUnknownVersionState((connecter) => newState = connecter, new OpenSslCryptoProvider());
                Assert.Throws<Alerts.AlertException>(() => state.HandleHandshakeRecord(ref buffer, ref writer));        
            }
        }
    }
}
