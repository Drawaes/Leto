using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Leto.Tls13.Internal;
using Leto.Tls13.RecordLayer;
using Leto.Tls13.State;
using Microsoft.Extensions.Logging;

namespace Leto.Tls13
{
    public class SecurePipelineConnection : IPipelineConnection
    {
        private IPipelineConnection _lowerConnection;
        private readonly Pipe _outputPipe;
        private readonly Pipe _inputPipe;
        private readonly Pipe _handshakePipe;
        private readonly Pipe _handshakeOutpipe;
        private IConnectionState _state;
        private bool _startedApplicationWrite;
        private SecurePipelineListener _listener;
        private ILogger<SecurePipelineConnection> _logger;
        private TaskCompletionSource<bool> _handshakeDone = new TaskCompletionSource<bool>();

        public SecurePipelineConnection(IPipelineConnection pipeline, PipelineFactory factory, SecurePipelineListener listener, ILogger<SecurePipelineConnection> logger)
        {
            _logger = logger;
            _listener = listener;
            _lowerConnection = pipeline;
            _outputPipe = factory.Create();
            _inputPipe = factory.Create();
            _handshakePipe = factory.Create();
            _handshakeOutpipe = factory.Create();
            StartReading();
        }

        public IPipelineReader Input => _outputPipe;
        public IPipelineWriter Output => _inputPipe;
        public Task HandshakeComplete => _handshakeDone.Task;

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
                        while (RecordProcessor.TryGetFrame(ref buffer, out messageBuffer))
                        {
                            var recordType = RecordProcessor.ReadRecord(ref messageBuffer, _state);
                            if (_state == null)
                            {
                                if (recordType != RecordType.Handshake)
                                {
                                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.unexpected_message, "Requre a handshake for first message");
                                }
                                _state = VersionStateFactory.GetNewStateMachine(messageBuffer, _listener, _logger);
                                HandshakeWriting();
                            }
                            _logger?.LogTrace($"Received TLS frame {recordType}");
                            if (recordType == RecordType.Handshake)
                            {
                                var writer = _handshakePipe.Alloc();
                                writer.Append(messageBuffer);
                                await writer.FlushAsync();
                                await HandshakeReading();
                                if (_state.State == StateType.HandshakeComplete && !_startedApplicationWrite)
                                {
                                    _logger?.LogInformation("Handshake complete starting application writing");
                                    ApplicationWriting();
                                    _startedApplicationWrite = true;
                                    _handshakeDone.SetResult(true);
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
                                _logger?.LogTrace("Writing Application Data");
                                var writer = _outputPipe.Alloc();
                                writer.Append(messageBuffer);
                                await writer.FlushAsync();
                                continue;
                            }
                            if (recordType == RecordType.ChangeCipherSpec)
                            {
                                var outbuffer = _lowerConnection.Output.Alloc();
                                var cipherBuffer = new byte[1];
                                cipherBuffer[0] = 1;
                                RecordProcessor.WriteRecord(ref outbuffer, RecordType.ChangeCipherSpec, cipherBuffer, _state);
                                await outbuffer.FlushAsync();
                                _state.HandleChangeCipherSpec(messageBuffer);
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
            catch(Exception ex)
            {
                _logger?.LogWarning(new EventId(1), ex, "There was an unhandled exception in the reading loop");
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
                while (Handshake.HandshakeProcessor.TryGetFrame(ref buffer, out messageBuffer, out handshakeType))
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
                            _logger?.LogTrace("Writing application frame");
                            var writer = _lowerConnection.Output.Alloc();
                            RecordProcessor.WriteRecord(ref writer, RecordType.Application, messageBuffer, _state);
                            await writer.FlushAsync();
                        }
                        _state.DataForCurrentScheduleSent.Set();
                        if (result.IsCompleted && buffer.IsEmpty)
                        {
                            var output = _lowerConnection.Output.Alloc();
                            Alerts.AlertException.WriteAlert(ref output, Alerts.AlertLevel.Warning, Alerts.AlertDescription.close_notify, _state);
                            await output.FlushAsync();
                            break;
                        }
                    }
                    finally
                    {
                        _inputPipe.AdvanceReader(buffer.Start, buffer.End);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger?.LogDebug($"Exception was thrown {ex}");
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
                            _logger?.LogTrace("Writing handshake frame");
                            writer = _lowerConnection.Output.Alloc();
                            RecordProcessor.WriteRecord(ref writer, RecordType.Handshake, messageBuffer, _state);
                            await writer.FlushAsync();
                        }
                        _state.DataForCurrentScheduleSent.Set();
                    }
                    catch(Exception ex)
                    {
                        _logger?.LogWarning(new EventId(2), ex, "The handshake loop had an exception");
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
            _logger?.LogTrace("Disposed connection");
            _lowerConnection.Dispose();
            GC.SuppressFinalize(this);
        }

        ~SecurePipelineConnection()
        {
            Dispose();
        }
    }
}
