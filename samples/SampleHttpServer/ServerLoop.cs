using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.IO.Pipelines.Samples;
using System.IO.Pipelines.Text.Primitives;
using System.Linq;
using System.Text;
using System.Text.Formatting;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.PlatformAbstractions;
using SampleHttpServer.Http;

namespace SampleHttpServer
{
    public class ServerLoop
    {
        static readonly byte[] _getMethod = Encoding.UTF8.GetBytes("GET");
        static readonly FileCache _cache = new FileCache();

        public static async Task HandleConnection(IPipelineConnection connection, ILoggerFactory loggerFactory)
        {
            var logger = loggerFactory?.CreateLogger<ServerLoop>();
            var httpParser = new HttpRequestParser(loggerFactory);
            var connectionId = Guid.NewGuid();
            using (var lScope = logger.BeginScope("Connection started", connectionId))
            {
                while (true)
                {
                    // Wait for data
                    var result = await connection.Input.ReadAsync();
                    var input = result.Buffer;
                    logger?.LogTrace("Http data received");
                    try
                    {
                        if (input.IsEmpty && result.IsCompleted)
                        {
                            logger?.LogTrace("No more data on the connection");
                            // No more data
                            break;
                        }

                        // Parse the input http request
                        var parseResult = httpParser.ParseRequest(ref input);

                        switch (parseResult)
                        {
                            case HttpRequestParser.ParseResult.Incomplete:
                                logger?.LogTrace("Incomplete parsed");
                                if (result.IsCompleted)
                                {
                                    // Didn't get the whole request and the connection ended
                                    throw new EndOfStreamException();
                                }
                                // Need more data
                                continue;
                            case HttpRequestParser.ParseResult.Complete:
                                logger?.LogTrace("Parsing completed");
                                break;
                            case HttpRequestParser.ParseResult.BadRequest:
                                logger?.LogTrace("Parsing bad request");
                                throw new Exception();
                            default:
                                break;
                        }


                        //// Writing directly to pooled buffers
                        //var output = connection.Output.Alloc();
                        //var formatter = new OutputFormatter<WritableBuffer>(output, EncodingData.InvariantUtf8);
                        //formatter.Append("HTTP/1.1 200 OK");
                        //formatter.Append("\r\nContent-Length: 13");
                        //formatter.Append("\r\nContent-Type: text/plain");
                        //formatter.Append("\r\n\r\n");
                        //formatter.Append("Hello, World!");
                        //await output.FlushAsync();
                        logger?.LogTrace("Http method is {method}",httpParser.Method);
                        if (httpParser.Method.Length == 3 && httpParser.Method.StartsWith(_getMethod))
                        {
                            var path = httpParser.Path.GetUtf8String();
                            logger?.LogTrace("Path is {path}", path);
                            var cacheItem = _cache.GetCacheItem(path);
                            if (cacheItem != null)
                            {
                                var output = connection.Output.Alloc();
                                var formatter = new OutputFormatter<WritableBuffer>(output, EncodingData.InvariantUtf8);
                                formatter.Append("HTTP/1.1 200 OK");
                                formatter.Append("\r\nContent-Length: ");
                                formatter.Append(cacheItem.Content.Length);
                                formatter.Append("\r\nContent-Type: ");
                                output.Write(cacheItem.ContentType);
                                formatter.Append("\r\n\r\n");
                                output.Write(cacheItem.Content);
                                logger?.LogTrace("Returning 200 ok {path}", path);
                                await output.FlushAsync();
                            }
                            else
                            {
                                var output = connection.Output.Alloc();
                                var formatter = new OutputFormatter<WritableBuffer>(output, EncodingData.InvariantUtf8);
                                formatter.Append("HTTP/1.1 404 NOT FOUND");
                                formatter.Append("\r\nContent-Length: 0");
                                formatter.Append("\r\n\r\n");
                                logger?.LogTrace("Returning 404 not found {path}", path);
                                await output.FlushAsync();
                            }
                        }
                        else
                        {
                            var output = connection.Output.Alloc();
                            var formatter = new OutputFormatter<WritableBuffer>(output, EncodingData.InvariantUtf8);
                            formatter.Append("HTTP/1.1 404 NOT FOUND");
                            formatter.Append("\r\nContent-Length: 0");
                            formatter.Append("\r\n\r\n");
                            await output.FlushAsync();
                        }
                        if (httpParser.RequestHeaders["Connection"] == "close")
                        {
                            connection.Output.Complete();
                        }
                        httpParser.Reset();
                    }
                    finally
                    {
                        // Consume the input
                        connection.Input.Advance(input.Start, input.End);
                    }
                }
            }
        }
    }
}
