using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipelines;
using System.Text;
using System.Text.Formatting;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting.Server;

namespace SocketServer
{
    public partial class HttpConnection<TContext>
    {
        private static readonly byte[] _http11Bytes = Encoding.UTF8.GetBytes("HTTP/1.1 ");
        private static readonly byte[] _chunkedEndBytes = Encoding.UTF8.GetBytes("0\r\n\r\n");
        private static readonly byte[] _endChunkBytes = Encoding.ASCII.GetBytes("\r\n");

        private readonly IPipeReader _input;
        private readonly IPipeWriter _output;
        private readonly IHttpApplication<TContext> _application;

        public RequestHeaderDictionary RequestHeaders => _parser.RequestHeaders;
        
        public ReadableBuffer HttpVersion => _parser.HttpVersion;
        public ReadableBuffer Path => _parser.Path;
        public ReadableBuffer Method => _parser.Method;

        // TODO: Check the http version
        public bool KeepAlive => true;
        
        private bool _autoChunk;

        private HttpRequestParser _parser = new HttpRequestParser();

        public HttpConnection(IHttpApplication<TContext> application, IPipeReader input, IPipeWriter output)
        {
            _application = application;
            _input = input;
            _output = output;
        }

        public IPipeReader Input => _input;

        public IPipeWriter Output => _output;

        public HttpRequestStream<TContext> RequestBody { get; set; }

        public HttpResponseStream<TContext> ResponseBody { get; set; }


        public async Task ProcessAllRequests()
        {
            Reset();

            while (true)
            {
                var result = await _input.ReadAsync();
                var buffer = result.Buffer;
                var consumed = buffer.Start;
                var examined = buffer.Start;

                try
                {
                    if (buffer.IsEmpty && result.IsCompleted)
                    {
                        // We're done with this connection
                        return;
                    }

                    var parserResult = _parser.ParseRequest(buffer, out consumed, out examined);

                    switch (parserResult)
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
                            // Done
                            break;
                        case HttpRequestParser.ParseResult.BadRequest:
                            // TODO: Don't throw here;
                            throw new Exception();
                        default:
                            break;
                    }

                }
                catch (Exception)
                {
                    StatusCode = 400;

                    await EndResponse();

                    return;
                }
                finally
                {
                    _input.Advance(consumed, examined);
                }

                var context = _application.CreateContext(this);

                try
                {
                    await _application.ProcessRequestAsync(context);
                }
                catch (Exception ex)
                {
                    StatusCode = 500;

                    _application.DisposeContext(context, ex);
                }
                finally
                {
                    await EndResponse();
                }

                if (!KeepAlive)
                {
                    break;
                }

                Reset();
            }
        }

        private async Task EndResponse()
        {
            var buffer = _output.Alloc();

            if (!HasStarted)
            {
                WriteBeginResponseHeaders(buffer);
            }

            if (_autoChunk)
            {
                WriteEndResponse(buffer);
            }

            await buffer.FlushAsync();
        }

        private void Reset()
        {
            //RequestBody = _requestBody;
            //ResponseBody = _responseBody;
            _parser.Reset();
            HasStarted = false;
            StatusCode = 200;
            _autoChunk = false;
            _method = null;
            _path = null;
        }

        public Task WriteAsync(Span<byte> data)
        {
            var buffer = _output.Alloc();

            if (!HasStarted)
            {
                WriteBeginResponseHeaders(buffer);
            }

            if (_autoChunk)
            {
                buffer.Append(data.Length, SymbolTable.InvariantUtf8, 'x');
                buffer.Write(_endChunkBytes);
                buffer.Write(data);
                buffer.Write(_endChunkBytes);
            }
            else
            {
                buffer.Write(data);
            }

            return FlushAsync(buffer);
        }

        public async Task FlushAsync(WritableBuffer buffer) => await buffer.FlushAsync();

        private void WriteBeginResponseHeaders(WritableBuffer buffer)
        {
            if (HasStarted)
            {
                return;
            }

            HasStarted = true;

            buffer.Write(_http11Bytes);
            var status = ReasonPhrases.ToStatusBytes(StatusCode);
            buffer.Write(status);

            _autoChunk = false;
        }

        private void WriteEndResponse(WritableBuffer buffer) => buffer.Write(_chunkedEndBytes);
    }
}