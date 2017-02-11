using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;

namespace SslStreamVsLeto
{
    public class CrossingTheStreams
    {
        const string certPath = "c:\\code\\leto\\data\\new.pfx";
        const string certPassword = "Test123t";
        private static Leto.Tls13.SecurePipeListener _listener;
        private static X509Certificate2 _certificate;
        private static PipeFactory _factory;
        private static byte[] _payload = new byte[1024];

        [Setup]
        public static void Setup()
        {
            _factory = new PipeFactory();
            _certificate = new X509Certificate2(certPath, certPassword);
            var certs = new Leto.Tls13.CertificateList();
            var provider = new Leto.Tls13.Certificates.OpenSsl11.CertificateProvider();
            certs.AddCertificate(provider.LoadPfx12(certPath, certPassword));
            _listener = new Leto.Tls13.SecurePipeListener(_factory, certs, null);
        }

        [Benchmark(Baseline = true)]
        public async Task Stream2Stream()
        {
            var pipe = new LoopbackPipeline(_factory);

            using (var server = new SslStream(pipe.ServerPipeline.GetStream(), false, Validate))
            using (var client = new SslStream(pipe.ClientPipeline.GetStream(), false, Validate))
            {
                var taskArray = new Task[2];
                taskArray[0] = server.AuthenticateAsServerAsync(_certificate, false, System.Security.Authentication.SslProtocols.Tls12, false);
                taskArray[1] = client.AuthenticateAsClientAsync("tls13.cetus.io");
                await Task.WhenAll(taskArray);
                Console.WriteLine($"Algo {client.CipherAlgorithm} strength {client.CipherStrength}");
            }
        }
        [Benchmark]
        public async Task Stream2Leto()
        {
            var pipe = new LoopbackPipeline(_factory);
            using (var secPipe = _listener.CreateSecurePipeline(pipe.ServerPipeline))
            using (var client = new SslStream(pipe.ClientPipeline.GetStream(), false, Validate))
            {
                var taskArray = new Task[2];
                taskArray[0] = secPipe.HandshakeComplete;
                taskArray[1] = client.AuthenticateAsClientAsync("tls13.cetus.io");
                await Task.WhenAll(taskArray);
            }
        }
        private static bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors policy)
        {

            return true;
        }
    }


}

