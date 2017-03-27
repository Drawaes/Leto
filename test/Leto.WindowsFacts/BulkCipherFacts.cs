using Leto.BulkCiphers;
using Leto.RecordLayer;
using Leto.Windows;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Leto.WindowsFacts
{
    public class BulkCipherFacts
    {
        private static readonly byte[] s_clientFinishedEncrypted = StringToByteArray("16  03  03  00  28  00  00  00  00  00  00  00  00  2D  77  23  0C  D7  E9  51  1C  26  76  A7  FF  9D  0B  43  A8  2C  A6  85  4B  A3  04  06  3B  6EA3  19  09  7E5F  B3  A9");
        private static readonly byte[] s_clientFinishedDecrypted = StringToByteArray("14  00  00  0C  A2  4D  7B  D4  50  17  A3  D5  2EDF  75  55");
        private static readonly byte[] s_key = StringToByteArray("C6  1A  42  06  56  A1  47  7D  BF  CC  45  B9  7B  96  DD  7E");
        private static readonly byte[] s_iv = StringToByteArray("31  8B  18  E9");
        private static readonly byte[] s_frameHeader = StringToByteArray("16  03  03  00  28");

        public static byte[] StringToByteArray(String hex)
        {
            hex = string.Join("", hex.Where(c => !char.IsWhiteSpace(c)));
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        [Fact]
        public async Task EncryptClientMessage()
        {
            var provider = new WindowsBulkKeyProvider();
            var cipher = SetIVAndKey(provider);
            using (var pipeFactory = new PipeFactory())
            {
                var pipe = pipeFactory.Create();
                var writer = pipe.Writer.Alloc();
                writer.Write(s_frameHeader);
                cipher.WriteNonce(ref writer);
                writer.Write(s_clientFinishedDecrypted);
                cipher.EncryptWithAuthData(ref writer, RecordType.Handshake, TlsVersion.Tls12, s_clientFinishedDecrypted.Length);
                await writer.FlushAsync();
                var reader = await pipe.Reader.ReadAsync();
                var buffer = reader.Buffer;
                Assert.Equal(s_clientFinishedEncrypted, buffer.ToArray());
            }
        }

        private static AeadBulkCipher SetIVAndKey(IBulkCipherKeyProvider provider)
        {
            var tempIv = new byte[12];
            s_iv.CopyTo(tempIv);
            return provider.GetCipher(BulkCipherType.AES_128_GCM, new System.Buffers.OwnedPinnedBuffer<byte>(s_key.Concat(tempIv).ToArray()).Buffer);
        }

        [Fact]
        public async Task DecryptClientMessage()
        {
            var provider = new WindowsBulkKeyProvider();
            var cipher = SetIVAndKey(provider);

            using (var pipeFactory = new PipeFactory())
            {
                var pipe = pipeFactory.Create();
                var writer = pipe.Writer.Alloc();
                writer.Write(s_clientFinishedEncrypted);
                await writer.FlushAsync();
                var reader = await pipe.Reader.ReadAsync();
                var buffer = reader.Buffer;
                cipher.Decrypt(ref buffer, true);
                var readerSpan = buffer.ToSpan();
                Assert.Equal(s_clientFinishedDecrypted, readerSpan.ToArray());
            }
        }
    }
}
