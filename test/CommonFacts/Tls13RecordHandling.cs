using System;
using System.Binary;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Leto;
using Leto.BulkCiphers;
using Xunit;

namespace CommonFacts
{
    public class Tls13RecordHandling
    {
        private static readonly byte[] s_key = "ad 19 00 5e 7f 4b 77 b6 78 26 6e 0e 2c ed 60 2d ad 19 00 5e 7f 4b 77 b6 78 26 6e 0e 2c ed 60 2d".HexToByteArray();
        private static readonly byte[] s_iv = "41 6c 48 f2 2c 0c 25 e1 bd 6a 53 0d".HexToByteArray();
        private static readonly byte[] s_message = Enumerable.Repeat<byte>(10, 100).ToArray();
        private static readonly byte[] s_messageRecord = "1C-90-0A-91-11-8F-E1-07-5E-C9-5D-0B-35-78-A5-5E-5A-1D-DC-D0-B9-B4-86-31-A2-35-29-6B-4B-15-51-B2-33-16-5A-60-51-77-AC-3A-38-2C-89-B1-1D-CB-42-2A-EC-8F-2F-7F-31-C6-39-F4-85-2B-68-4A-39-69-D5-B3-87-34-EE-83-8D-0F-A5-D3-48-5B-68-60-A5-54-71-CD-93-3A-B3-3F-7E-FE-46-24-07-BE-14-3D-3A-5C-39-A4-C8-EB-FB-E3-64-A9-86-1D-14-2E-7E-DA-FD-7D-1E-E9-3F-28-EF-0D-E2".HexToByteArray();
        private static readonly byte[] s_messageHeader = "17-03-01-00-75".HexToByteArray();
        private static readonly byte[] s_largeMessage = Enumerable.Repeat<byte>(11, 18000).ToArray();

        public static async Task WriteHandshakeRecord(IBulkCipherKeyProvider provider)
        {
            using (var cipher = SetIVAndKey(provider))
            using (var pipeFactory = new PipeFactory())
            {
                var pipe = pipeFactory.Create();
                var writer = pipe.Writer.Alloc();
                writer.Write(s_message);
                await writer.FlushAsync();

                var keyPair = new KeyPair()
                {
                    ReadKey = cipher,
                    WriteKey = cipher
                };
                var recordHandler = new Leto.RecordLayer.Tls13RecordHandler(keyPair, TlsVersion.Tls13Draft18, pipe.Writer);
                recordHandler.WriteRecords(pipe.Reader, Leto.RecordLayer.RecordType.Handshake);

                var result = pipe.Reader.TryRead(out ReadResult readResult);
                Assert.True(result);
                var header = readResult.Buffer.First.Span.Read<Leto.RecordLayer.RecordHeader>();
                Assert.Equal(Leto.RecordLayer.RecordType.Application, header.RecordType);
                var sizeShouldBe = 5 + s_messageRecord.Length;
                Assert.Equal(sizeShouldBe, readResult.Buffer.Length);
                var returnResult = readResult.Buffer.Slice(5).ToArray();
                Assert.Equal(s_messageRecord, returnResult);
                pipe.Reader.Advance(readResult.Buffer.End);
            }
        }

        public static async Task WriteMultiFrameHandshakeRecord(IBulkCipherKeyProvider provider)
        {
            using (var cipher = SetIVAndKey(provider))
            using (var pipeFactory = new PipeFactory())
            {
                var pipe = pipeFactory.Create();
                var writer = pipe.Writer.Alloc();
                writer.Write(s_largeMessage);
                await writer.FlushAsync();

                var keyPair = new KeyPair()
                {
                    ReadKey = cipher,
                    WriteKey = cipher
                };
                var recordHandler = new Leto.RecordLayer.Tls13RecordHandler(keyPair, TlsVersion.Tls13Draft18, pipe.Writer);
                recordHandler.WriteRecords(pipe.Reader, Leto.RecordLayer.RecordType.Handshake);

                var result = pipe.Reader.TryRead(out ReadResult readResult);
                Assert.True(result);
                var header = readResult.Buffer.First.Span.Read<Leto.RecordLayer.RecordHeader>();
                var secondMessage = readResult.Buffer.Slice(5 + header.Length);
                var secondHeader = secondMessage.ToSpan().Read<Leto.RecordLayer.RecordHeader>();
                Assert.Equal(Leto.RecordLayer.RecordType.Application, secondHeader.RecordType);
                Assert.Equal(5 + secondHeader.Length, secondMessage.Length);
                pipe.Reader.Advance(readResult.Buffer.End);
            }
        }

        private static AeadBulkCipher SetIVAndKey(IBulkCipherKeyProvider provider)
        {
            var keyBuffer = new System.Buffers.OwnedPinnedBuffer<byte>(s_key.Concat(s_iv).ToArray());
            return provider.GetCipher<AeadTls13BulkCipher>(BulkCipherType.AES_256_GCM, keyBuffer);
        }

        public static async Task ReadHandshakeRecord(IBulkCipherKeyProvider provider)
        {
            using (var cipher = SetIVAndKey(provider))
            using (var pipeFactory = new PipeFactory())
            {
                var pipe = pipeFactory.Create();
                var writer = pipe.Writer.Alloc();
                writer.Write(s_messageHeader);
                writer.Write(s_messageRecord);
                await writer.FlushAsync();

                var keyPair = new KeyPair()
                {
                    ReadKey = cipher
                };
                var recordHandler = new Leto.RecordLayer.Tls13RecordHandler(keyPair, TlsVersion.Tls13Draft18, pipe.Writer);
                var readResult = await pipe.Reader.ReadAsync();
                var buffer = readResult.Buffer;
                var recordResult = recordHandler.ReadRecord(ref buffer, out ReadableBuffer messageBuffer);

                Assert.Equal(0, buffer.Length);
                Assert.Equal(Leto.RecordLayer.RecordState.Record, recordResult);
                Assert.Equal(Leto.RecordLayer.RecordType.Handshake, recordHandler.CurrentRecordType);
                var result = messageBuffer.ToArray();
                Assert.Equal(s_message, result);
                pipe.Reader.Advance(buffer.End);

            }
        }

        class KeyPair : IKeyPair
        {
            public AeadBulkCipher WriteKey { get; set; }
            public AeadBulkCipher ReadKey { get; set; }
        }
    }
}
