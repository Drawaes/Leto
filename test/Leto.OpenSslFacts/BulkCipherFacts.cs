using Leto.Hash;
using Leto.RecordLayer;
using System;
using System.IO.Pipelines;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace Leto.OpenSslFacts
{
    public class BulkCipherFacts
    {
        private static readonly byte[] s_clientFinishedEncrypted = StringToByteArray("16  03  03  00  28  00  00  00  00  00  00  00  00  2D  77  23  0C  D7  E9  51  1C  26  76  A7  FF  9D  0B  43  A8  2C  A6  85  4B  A3  04  06  3B  6EA3  19  09  7E5F  B3  A9");
        private static readonly byte[] s_clientFinishedDecrypted = StringToByteArray("14  00  00  0C  A2  4D  7B  D4  50  17  A3  D5  2EDF  75  55");
        private static readonly byte[] s_key = StringToByteArray("C6  1A  42  06  56  A1  47  7D  BF  CC  45  B9  7B  96  DD  7E");
        private static readonly byte[] s_iv = StringToByteArray("31  8B  18  E9");
        private static readonly byte[] s_frameHeader = StringToByteArray("16  03  03  00  28");

        [Fact]
        public async Task EncryptClientMessage()
        {
            var provider = new BulkCipher.OpenSslBulkKeyProvider();
            var cipher = provider.GetCipher(BulkCipher.BulkCipherType.AES_128_GCM);
            SetIVAndKey(cipher);
            using (var pipeFactory = new PipeFactory())
            {
                var pipe = pipeFactory.Create();
                var writer = pipe.Writer.Alloc();
                writer.Write(s_frameHeader);
                cipher.WriteNonce(ref writer);
                writer.Write(s_clientFinishedDecrypted);
                cipher.EncryptWithAuthData(ref writer, RecordType.Handshake, 0x0303, s_clientFinishedDecrypted.Length);
                await writer.FlushAsync();
                var reader = await pipe.Reader.ReadAsync();
                var buffer = reader.Buffer;
                Assert.Equal(s_clientFinishedEncrypted, buffer.ToArray());
            }
        }

        private static void SetIVAndKey(BulkCipher.AeadBulkCipher cipher)
        {
            var tempIv = new byte[12];
            for (int i = 0; i < s_iv.Length; i++)
            {
                tempIv[i] = (byte)(s_iv[i] ^ 0x00);
            }
            //We need to do this because we use the sequence xored but chrome uses the 
            //sequence both are valid but the test data is from chrome to a server connection
            for(int i = s_iv.Length; i < tempIv.Length;i++)
            {
                tempIv[i] = (byte)(tempIv[i] ^ 0x00);
            }
            cipher.SetKey(s_key);
            cipher.SetIV(tempIv);
        }

        [Fact]
        public async Task DecryptClientMessage()
        {
            var provider = new BulkCipher.OpenSslBulkKeyProvider();
            var cipher = provider.GetCipher(BulkCipher.BulkCipherType.AES_128_GCM);
            SetIVAndKey(cipher);            

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

        public static byte[] StringToByteArray(String hex)
        {
            hex = string.Join("", hex.Where(c => !char.IsWhiteSpace(c)));
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}
