using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Leto.Tls13;
using Xunit;

namespace Leto.Tls13Facts
{
    public class SocketFacts
    {
        [Fact]
        public void WaitForConnectionFact()
        {
            using (var factory = new PipelineFactory())
            using (var serverContext = new SecurePipelineListener(factory))
            using (var socketClient = new System.IO.Pipelines.Networking.Sockets.SocketListener(factory))
            {
                var ipEndPoint = new IPEndPoint(IPAddress.Loopback, 443);
                socketClient.OnConnection(async s =>
                {
                    var sp = serverContext.CreateSecurePipeline(s);
                    await Echo(sp);
                });
                socketClient.Start(ipEndPoint);
                Console.ReadLine();
            }
        }

        private async Task Echo(SecurePipelineConnection pipeline)
        {
            try
            {
                while (true)
                {
                    var result = await pipeline.Input.ReadAsync();
                    var request = result.Buffer;

                    if (request.IsEmpty && result.IsCompleted)
                    {
                        pipeline.Input.Advance(request.End);
                        break;
                    }
                    int len = request.Length;
                    var response = pipeline.Output.Alloc();
                    response.Append(request);
                    await response.FlushAsync();
                    pipeline.Input.Advance(request.End);
                }
                pipeline.Input.Complete();
                pipeline.Output.Complete();
            }
            catch (Exception ex)
            {
                pipeline.Input.Complete(ex);
                pipeline.Output.Complete(ex);
            }
        }
    }
}
