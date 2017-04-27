using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Leto;
using Xunit;

namespace CommonFacts
{
    public class FullConnectionSSlStreamFacts
    {
        private static byte[] s_SmallMessage = Encoding.ASCII.GetBytes("The quick brown fox jumped over the lazy dog.");
        private static byte[] s_MessageLargerThanOneBuffer = Enumerable.Repeat(s_SmallMessage, 120).SelectMany(t => t).ToArray();

        public static Task SmallMessageFact(PipeFactory factory, SecurePipeListener listener) => ConnectWithSslStream(factory, listener, s_SmallMessage);
        public static Task MultiBufferFact(PipeFactory factory, SecurePipeListener listener) => ConnectWithSslStream(factory, listener, s_MessageLargerThanOneBuffer);

        private static async Task ConnectWithSslStream(PipeFactory factory, SecurePipeListener listener, byte[] message)
        {
            var loopback = new LoopbackPipeline(factory);
            var stream = loopback.ClientPipeline.GetStream();
            var secureConnection = listener.CreateConnection(loopback.ServerPipeline);
            var ignore = Echo(secureConnection);
            using (var sslStream = new SslStream(stream, false, CertVal))
            {
                await sslStream.AuthenticateAsClientAsync("localhost");

                await sslStream.WriteAsync(message, 0, message.Length);
                var returnBuffer = new byte[message.Length];
                var byteCount = 0;
                while (byteCount < message.Length)
                {
                    byteCount += await sslStream.ReadAsync(returnBuffer, byteCount, returnBuffer.Length - byteCount);
                }
                Assert.Equal(message, returnBuffer);
            }
            secureConnection.Result.Dispose();
        }

        private static bool CertVal(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors policyError) => true;

        private static async Task Echo(Task<SecurePipeConnection> connectionTask)
        {
            var connection = await connectionTask;
            var readResult = await connection.Input.ReadAsync();
            var writer = connection.Output.Alloc();
            writer.Append(readResult.Buffer);
            await writer.FlushAsync();
        }
    }
}
