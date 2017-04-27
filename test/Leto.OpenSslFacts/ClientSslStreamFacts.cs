using Leto.OpenSsl11;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Xunit;
using CommonFacts;
using System.Diagnostics;
using Leto.KeyExchanges;

namespace Leto.OpenSslFacts
{
    public class ClientSslStreamFacts
    {
        [Theory]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.RSA_AES_128_GCM_SHA256, null)]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.RSA_AES_256_GCM_SHA384, null)]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, new NamedGroup[] { NamedGroup.secp256r1 })]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, new NamedGroup[] { NamedGroup.secp384r1 })]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, new NamedGroup[] { NamedGroup.x25519 })]
        [InlineData(CipherSuites.PredefinedCipherSuites.PredefinedSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, null)]
        public async Task HandshakeCompletes(CipherSuites.PredefinedCipherSuites.PredefinedSuite suite, NamedGroup[] supportedNamedGroups)
        {
            using (var factory = new PipeFactory())
            using (var listener = new OpenSslSecurePipeListener(Data.Certificates.RSACertificate, factory))
            {
                if (supportedNamedGroups != null)
                {
                    listener.CryptoProvider.KeyExchangeProvider.SetSupportedNamedGroups(supportedNamedGroups);
                }
                listener.CryptoProvider.CipherSuites.SetCipherSuites(new CipherSuites.CipherSuite[] { CipherSuites.PredefinedCipherSuites.GetSuiteByName(suite) });
                await FullConnectionSSlStreamFacts.SmallMessageFact(factory, listener);
            }
        }

        [Fact]
        public async Task EphemeralSessionProvider()
        {
            using (var factory = new PipeFactory())
            using (var listener = new OpenSslSecurePipeListener(Data.Certificates.RSACertificate, factory))
            {
                listener.UseEphemeralSessionProvider();
                await FullConnectionSSlStreamFacts.SmallMessageFact(factory, listener);
                await FullConnectionSSlStreamFacts.SmallMessageFact(factory, listener);
            }
        }
        
        [Fact]
        public async Task MultiBuffer()
        {
            using (var factory = new PipeFactory())
            using (var listener = new OpenSslSecurePipeListener(Data.Certificates.RSACertificate, factory))
            {
                await FullConnectionSSlStreamFacts.MultiBufferFact(factory, listener);
            }
        }

        //[Fact]
        public void SocketTest()
        {
            var readData = string.Empty;
            var wait = new System.Threading.ManualResetEvent(false);
            using (var factory = new PipeFactory())
            using (var listener = new System.IO.Pipelines.Networking.Sockets.SocketListener())
            using (var secureListener = new OpenSslSecurePipeListener(Data.Certificates.RSACertificate))
            {
                listener.OnConnection(async (conn) =>
                {
                    var pipe = await secureListener.CreateConnection(conn);
                    Console.WriteLine("Handshake Done");
                    var reader = await pipe.Input.ReadAsync();
                    readData = Encoding.UTF8.GetString(reader.Buffer.ToArray());
                    var writer = pipe.Output.Alloc();
                    writer.Append(reader.Buffer);
                    await writer.FlushAsync();
                    wait.Set();
                });
                listener.Start(new IPEndPoint(IPAddress.Any, 443));

                var process = new Process();
                process.StartInfo.WorkingDirectory = @"..\..\..\..\..\external\nss\";
                process.StartInfo.FileName = @"..\..\..\..\..\external\nss\RunTest.bat";
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.Start();
                var output = process.StandardOutput.ReadToEnd();
                var out2 = process.StandardError.ReadToEnd();
                wait.WaitOne();
                process.Kill();
                Assert.Equal("", readData);
            }
        }
    }
}
