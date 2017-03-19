using Leto.OpenSsl11;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Leto.OpenSslFacts
{
    public class ClientSslStreamFacts
    {
        [Fact]
        public async Task HandshakeCompletes()
        {
            using (var factory = new PipeFactory())
            {
                var loopback = new LoopbackPipeline(factory);
                var stream = loopback.ClientPipeline.GetStream();
                var secureConnection = new SecurePipeConnection(factory, loopback.ServerPipeline, new OpenSslSecurePipeListener(Data.Certificates.RSACertificate));
                using (var sslStream = new SslStream(stream, false, CertVal))
                {
                    await sslStream.AuthenticateAsClientAsync("localhost");
                }
            }
        }

        private bool CertVal(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors policyError)
        {
            return true;
        }
    }
}
