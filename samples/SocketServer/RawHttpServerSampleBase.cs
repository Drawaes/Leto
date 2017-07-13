using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Net;
using System.Text;
using System.Text.Formatting;
using System.Threading.Tasks;

namespace SocketServer
{
    public abstract class RawHttpServerSampleBase //: ISample
    {
        private byte[] _outputContent;
        private string _contentLength;

        public RawHttpServerSampleBase(string filename)
        {
            _outputContent = File.ReadAllBytes(filename);
            _contentLength = $"\r\nContent-Length: {_outputContent.Length}";
        }


        public async Task Run(IPAddress address)
        {
            Console.WriteLine($"Listening on port 5000");
            await Start(new IPEndPoint(address, 5000));
            Console.ReadLine();
            await Stop();
        }

        protected abstract Task Start(IPEndPoint ipEndpoint);

        protected abstract Task Stop();

        protected async Task ProcessConnection(IPipeConnection connection)
        {
            var httpParser = new HttpRequestParser();
            while (true)
            {
                // Wait for data
                var result = await connection.Input.ReadAsync();
                var input = result.Buffer;
                var consumed = input.Start;
                var examined = input.Start;

                try
                {
                    if (input.IsEmpty && result.IsCompleted)
                    {
                        // No more data
                        break;
                    }

                    // Parse the input http request
                    var parseResult = httpParser.ParseRequest(input, out consumed, out examined);

                    switch (parseResult)
                    {
                        case HttpRequestParser.ParseResult.Incomplete:
                            if (result.IsCompleted)
                            {
                                // Didn't get the whole request and the connection ended
                                throw new EndOfStreamException();
                            }
                            // Need more data
                            continue;
                        case HttpRequestParser.ParseResult.Complete:
                            break;
                        case HttpRequestParser.ParseResult.BadRequest:
                            throw new Exception();
                        default:
                            break;
                    }

                    // Writing directly to pooled buffers
                    var output = connection.Output.Alloc();
                    var formatter = new OutputFormatter<WritableBuffer>(output, SymbolTable.InvariantUtf8);
                    formatter.Append("HTTP/1.1 200 OK");
                    formatter.Append(_contentLength);
                    formatter.Append("\r\nContent-Type: text/plain");
                    formatter.Append("\r\nConnection: keep-alive");
                    formatter.Append("\r\n\r\n");
                    output.Write(_outputContent);
                    await output.FlushAsync();

                    httpParser.Reset();
                }
                finally
                {
                    // Consume the input
                    connection.Input.Advance(consumed, examined);
                }
            }
        }
    }
}
