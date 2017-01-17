using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Leto.Tls13.Internal;
using Leto.Tls13.RecordLayer;
using Leto.Tls13.State;

namespace Leto.Tls13
{
    public class SecurePipelineConnection : IPipelineConnection
    {
        private IPipelineConnection _lowerConnection;
        private RecordProcessor _recordHandler;
        private readonly Pipe _outputPipe;
        private readonly Pipe _inputPipe;
        private readonly Pipe _handshakePipe;
        private readonly Pipe _handshakeOutpipe;
        private IConnectionState _state;
        private bool _startedApplicationWrite;

        public SecurePipelineConnection(IConnectionState state, IPipelineConnection pipeline, PipelineFactory factory, SecurePipelineListener listener)
        {
            _lowerConnection = pipeline;
            _outputPipe = factory.Create();
            _inputPipe = factory.Create();
            _handshakePipe = factory.Create();
            _handshakeOutpipe = factory.Create();
            _state = state;
            _recordHandler = new RecordProcessor(_state);
            HandshakeWriting();
            StartReading();
        }

        public IPipelineReader Input => _outputPipe;
        public IPipelineWriter Output => _inputPipe;

        private async void StartReading()
        {
            try
            {
                while (true)
                {
                    var result = await _lowerConnection.Input.ReadAsync();
                    var buffer = result.Buffer;
                    try
                    {
                        ReadableBuffer messageBuffer;
                        while (_recordHandler.TryGetFrame(ref buffer, out messageBuffer))
                        {
                            var recordType = _recordHandler.ReadRecord(ref messageBuffer);
                            Console.WriteLine($"Received TLS frame {recordType}");
                            if (recordType == RecordType.Handshake)
                            {
                                var writer = _handshakePipe.Alloc();
                                writer.Append(messageBuffer);
                                await writer.FlushAsync();
                                await HandshakeReading();
                                if (_state.State == StateType.HandshakeComplete && !_startedApplicationWrite)
                                {
                                    ApplicationWriting();
                                    _startedApplicationWrite = true;
                                }
                                continue;
                            }
                            if (recordType == RecordType.Alert)
                            {
                                _state.HandleAlertMessage(messageBuffer);
                                continue;
                            }
                            if (recordType == RecordType.Application)
                            {
                                var writer = _outputPipe.Alloc();
                                writer.Append(messageBuffer);
                                await writer.FlushAsync();
                                continue;
                            }
                            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message, $"Unknown message type {recordType}");
                        }
                        if (result.IsCompleted)
                        {
                            return;
                        }
                    }
                    finally
                    {
                        _lowerConnection.Input.Advance(buffer.Start, buffer.End);
                    }
                }
            }
            catch
            {
                //nom nom
                Dispose();
            }
        }

        private async Task HandshakeReading()
        {
            var result = await _handshakePipe.ReadAsync();
            var buffer = result.Buffer;
            try
            {
                ReadableBuffer messageBuffer;
                Handshake.HandshakeType handshakeType;
                while (Handshake.HandshakeProcessor.TryGetFrame(ref buffer, _state, out messageBuffer, out handshakeType))
                {
                    await _state.HandleHandshakeMessage(handshakeType, messageBuffer, _handshakeOutpipe);
                }
            }
            finally
            {
                _handshakePipe.AdvanceReader(buffer.Start, buffer.End);
            }
        }

        private async void ApplicationWriting()
        {
            try
            {
                while (true)
                {
                    var result = await _inputPipe.ReadAsync();
                    var buffer = result.Buffer;
                    try
                    {
                        while (buffer.Length > 0)
                        {
                            ReadableBuffer messageBuffer;
                            if (buffer.Length <= RecordProcessor.PlainTextMaxSize)
                            {
                                messageBuffer = buffer;
                                buffer = buffer.Slice(buffer.End);
                            }
                            else
                            {
                                messageBuffer = buffer.Slice(0, RecordProcessor.PlainTextMaxSize);
                                buffer = buffer.Slice(RecordProcessor.PlainTextMaxSize);
                            }
                            var writer = _lowerConnection.Output.Alloc();
                            _recordHandler.WriteRecord(ref writer, RecordType.Application, messageBuffer);
                            await writer.FlushAsync();
                        }
                        _state.DataForCurrentScheduleSent.Set();
                        if (result.IsCompleted && buffer.IsEmpty)
                        {
                            //var output = _lowerConnection.Output.Alloc();
                            //Alerts.AlertException.WriteAlert(_recordHandler, ref output, Alerts.AlertLevel.Warning, Alerts.AlertDescription.close_notify);
                            //await output.FlushAsync();
                            break;
                        }
                    }
                    finally
                    {
                        _inputPipe.AdvanceReader(buffer.Start, buffer.End);
                    }
                }
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Exception was thrown {ex}");
                //Nom Nom
            }
            _lowerConnection.Output.Complete();
        }

        private async void HandshakeWriting()
        {
            var writer = _handshakeOutpipe.Alloc();
            _state.StartHandshake(ref writer);
            if (writer.BytesWritten > 0)
            {
                await writer.FlushAsync();
            }
            else
            {
                writer.Commit();
            }
            while (true)
            {
                while (true)
                {
                    var result = await _handshakeOutpipe.ReadAsync();
                    var buffer = result.Buffer;
                    if (result.IsCompleted && result.Buffer.IsEmpty)
                    {
                        break;
                    }
                    try
                    {
                        while (buffer.Length > 0)
                        {
                            ReadableBuffer messageBuffer;
                            if (buffer.Length <= RecordProcessor.PlainTextMaxSize)
                            {
                                messageBuffer = buffer;
                                buffer = buffer.Slice(buffer.End);
                            }
                            else
                            {
                                messageBuffer = buffer.Slice(0, RecordProcessor.PlainTextMaxSize);
                                buffer = buffer.Slice(RecordProcessor.PlainTextMaxSize);
                            }
                            writer = _lowerConnection.Output.Alloc();
                            _recordHandler.WriteRecord(ref writer, RecordType.Handshake, messageBuffer);
                            await writer.FlushAsync();
                        }
                        _state.DataForCurrentScheduleSent.Set();
                    }
                    finally
                    {
                        _handshakeOutpipe.AdvanceReader(buffer.Start, buffer.End);
                    }
                }
            }
        }

        public void Dispose()
        {
            Console.WriteLine("Disposed connection");
            _lowerConnection.Dispose();
            GC.SuppressFinalize(this);
        }

        ~SecurePipelineConnection()
        {
            Dispose();
        }
    }
}
