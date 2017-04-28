using System;
using System.Binary;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Leto;
using Xunit;

namespace CommonFacts
{
    public class BadHelloFacts
    {
        private static readonly byte[] s_clientGoodMessage = "16-03-03-00-A0-01-00-00-9C-03-03-59-02-FE-F1-FB-31-E0-E5-E3-EA-4F-6D-D0-E9-BD-56-DE-C6-A3-0C-09-B3-BD-20-DA-5E-E7-F7-96-E4-D3-AB-00-00-2A-C0-2C-C0-2B-C0-30-C0-2F-00-9F-00-9E-C0-24-C0-23-C0-28-C0-27-C0-0A-C0-09-C0-14-C0-13-00-9D-00-9C-00-3D-00-3C-00-35-00-2F-00-0A-01-00-00-49-00-00-00-0E-00-0C-00-00-09-6C-6F-63-61-6C-68-6F-73-74-00-0A-00-08-00-06-00-1D-00-17-00-18-00-0B-00-02-01-00-00-0D-00-14-00-12-04-01-05-01-02-01-04-03-05-03-02-03-02-02-06-01-06-03-00-23-00-00-00-17-00-00-FF-01-00-01-00".HexToByteArray();
        private static readonly byte[] s_extraBytesAtEnd = "16-03-03-00-A2-01-00-00-9E-03-03-59-02-FE-F1-FB-31-E0-E5-E3-EA-4F-6D-D0-E9-BD-56-DE-C6-A3-0C-09-B3-BD-20-DA-5E-E7-F7-96-E4-D3-AB-00-00-2A-C0-2C-C0-2B-C0-30-C0-2F-00-9F-00-9E-C0-24-C0-23-C0-28-C0-27-C0-0A-C0-09-C0-14-C0-13-00-9D-00-9C-00-3D-00-3C-00-35-00-2F-00-0A-01-00-00-49-00-00-00-0E-00-0C-00-00-09-6C-6F-63-61-6C-68-6F-73-74-00-0A-00-08-00-06-00-1D-00-17-00-18-00-0B-00-02-01-00-00-0D-00-14-00-12-04-01-05-01-02-01-04-03-05-03-02-03-02-02-06-01-06-03-00-23-00-00-00-17-00-00-FF-01-00-01-00-FF-FF".HexToByteArray();
        private static readonly byte[] s_StartedWithApplication = "17-03-03-00-A2-01-00-00-9E-03-03-59-02-FE-F1-FB-31-E0-E5-E3-EA-4F-6D-D0-E9-BD-56-DE-C6-A3-0C-09-B3-BD-20-DA-5E-E7-F7-96-E4-D3-AB-00-00-2A-C0-2C-C0-2B-C0-30-C0-2F-00-9F-00-9E-C0-24-C0-23-C0-28-C0-27-C0-0A-C0-09-C0-14-C0-13-00-9D-00-9C-00-3D-00-3C-00-35-00-2F-00-0A-01-00-00-49-00-00-00-0E-00-0C-00-00-09-6C-6F-63-61-6C-68-6F-73-74-00-0A-00-08-00-06-00-1D-00-17-00-18-00-0B-00-02-01-00-00-0D-00-14-00-12-04-01-05-01-02-01-04-03-05-03-02-03-02-02-06-01-06-03-00-23-00-00-00-17-00-00-FF-01-00-01-00-FF-FF".HexToByteArray();

        public static async Task SendHelloWithExtraTrailingBytes(SecurePipeListener listener)
        {
            var exception = await Assert.ThrowsAsync<Leto.Alerts.AlertException>(async () => await TestForAlert(listener, s_extraBytesAtEnd));
            Assert.Equal(Leto.Alerts.AlertLevel.Fatal, exception.Level);
            Assert.Equal(Leto.Alerts.AlertDescription.decode_error, exception.Description);
        }

        public static async Task StartWithApplicationRecord(SecurePipeListener listener)
        {
            var exception = await Assert.ThrowsAsync<Leto.Alerts.AlertException>(async () => await TestForAlert(listener, s_StartedWithApplication));
            Assert.Equal(Leto.Alerts.AlertLevel.Fatal, exception.Level);
            Assert.Equal(Leto.Alerts.AlertDescription.unexpected_message, exception.Description);
        }

        private static async Task TestForAlert(SecurePipeListener listener, byte[] messageToSend)
        {
            using (var pipeFactory = new PipeFactory())
            {

                var connection = new LoopbackPipeline(pipeFactory);
                var secureConnection = listener.CreateConnection(connection.ServerPipeline);

                var writer = connection.ClientPipeline.Output.Alloc();
                writer.Write(messageToSend);
                await writer.FlushAsync();
                var result = await connection.ClientPipeline.Input.ReadAsync();
                var returnMessage = new Span<byte>(result.Buffer.ToArray());
                var header = returnMessage.Read<Leto.RecordLayer.RecordHeader>();
                               
                Assert.Equal(Leto.RecordLayer.RecordType.Alert, header.RecordType);

                var exception = new Leto.Alerts.AlertException(returnMessage.Slice(Marshal.SizeOf<Leto.RecordLayer.RecordHeader>()));
                connection.ClientPipeline.Input.Advance(result.Buffer.End);
                var closeConnection = await secureConnection;
                closeConnection.Dispose();
                throw exception;
            }
        }
    }
}
