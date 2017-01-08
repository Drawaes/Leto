using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13;
using Leto.Tls13.BulkCipher;
using Leto.Tls13.BulkCipher.OpenSsl11;
using Leto.Tls13.RecordLayer;
using Leto.Tls13.State;
using Xunit;

namespace Leto.Tls13Facts
{
    public class RecordLayerFacts
    {
        const string plaintextHex = "1503010005F0F1F2F3F4";
        // Random key and IV; hand-encoded ciphertext for the above plaintext
        const string keyHex = "45c71e5819170d622a9f4e3a089a0beb";
        const string ivHex = "2b7fbbf689f240e3e7aa44a6";
        const int paddingLength = 4;
        const int sequenceChange = 17;
        const string ciphertext0Hex = "1703010016621a75932c037ff74d2a9ec7776790e09dcd4811db97";
        const string ciphertext1Hex = "170301001a621a75932c03076e386b3cebbb8dbf2f37e49ad3e82a70a17833";
        const string ciphertext2Hex = "170301001a1da650d5da822b7f4eba67f954767fcbbbd4c4bc7f1c61daf701";

        static byte[] iv = HkdfFacts.StringToByteArray(ivHex);
        static byte[] key = HkdfFacts.StringToByteArray(keyHex);
        static byte[] message0 = HkdfFacts.StringToByteArray(ciphertext0Hex);
        static byte[] message1 = HkdfFacts.StringToByteArray(ciphertext1Hex);
        static byte[] message2 = HkdfFacts.StringToByteArray(ciphertext2Hex);
        static byte[] plainText = HkdfFacts.StringToByteArray(plaintextHex);
        private static SecurePipelineListener _listener = new SecurePipelineListener(null, null);

        [Fact]
        public void TestRecordDecrypt()
        {
            var prov = new BulkCipherProvider();
            var bKey = prov.GetCipherKey(BulkCipherType.AES_128_GCM);
            bKey.SetKey(key, KeyMode.Decryption);
            bKey.SetIV(iv);
            using (var factory = new PipelineFactory())
            {
                var pipe = factory.Create();
                var buffer = pipe.Alloc();
                buffer.Write(message1);
                buffer.FlushAsync().Wait();
                var reader = pipe.ReadAsync();
                var result = reader.GetResult().Buffer;
                var state = new ConnectionState(_listener);
                var recordHandler = new RecordProcessor(state);
                state.ReadKey = bKey;
                var header = recordHandler.ReadRecord(ref result);
                Assert.Equal(RecordType.Alert, header);
                Assert.Equal<byte>(plainText.Skip(5), result.ToArray());
            }
        }

        [Fact]
        public void TestRecordEncryptNoPadding()
        {
            var prov = new BulkCipherProvider();
            var bKey = prov.GetCipherKey(BulkCipherType.AES_128_GCM);
            bKey.SetKey(key, KeyMode.Encryption);
            bKey.SetIV(iv);
            using (var factory = new PipelineFactory())
            {
                var pipe = factory.Create();
                var pipeWriter = factory.Create();
                var state = new ConnectionState(_listener);
                var recordHandler = new RecordProcessor(state);
                state.WriteKey = bKey;
                var buff = pipe.Alloc();
                var buffWrite = pipeWriter.Alloc();
                buffWrite.Write(plainText);
                var reader = buffWrite.AsReadableBuffer();
                recordHandler.WriteRecord(ref buff, (RecordType)plainText[0], reader.Slice(5));
                var result = buff.AsReadableBuffer().ToArray();
                Assert.Equal<byte>(message0, result);
                buff.FlushAsync().Wait();
            }
        }

        [Fact]
        public void TestRecordEncryptWithPadding()
        {
            var prov = new BulkCipherProvider();
            var bKey = prov.GetCipherKey(BulkCipherType.AES_128_GCM);
            bKey.SetKey(key, KeyMode.Encryption);
            bKey.SetIV(iv);
            bKey.WithPadding(paddingLength);
            using (var factory = new PipelineFactory())
            {
                var pipe = factory.Create();
                var pipeWriter = factory.Create();
                var state = new ConnectionState(_listener);
                var recordHandler = new RecordProcessor(state);
                state.WriteKey = bKey;
                var buff = pipe.Alloc();
                var buffWrite = pipeWriter.Alloc();
                buffWrite.Write(plainText);
                var reader = buffWrite.AsReadableBuffer();
                recordHandler.WriteRecord(ref buff, (RecordType)plainText[0], reader.Slice(5));
                var result = buff.AsReadableBuffer().ToArray();
                buff.FlushAsync().Wait();
                Assert.Equal<byte>(message1, result);
            }
        }

        [Fact]
        public void TestRecordEncryptSequenceChange()
        {
            var prov = new BulkCipherProvider();
            var bKey = prov.GetCipherKey(BulkCipherType.AES_128_GCM);
            bKey.SetKey(key, KeyMode.Encryption);
            bKey.SetIV(iv);
            bKey.WithPadding(paddingLength);
            for (int i = 0; i < sequenceChange; i++)
            {
                bKey.IncrementSequence();
            }
            using (var factory = new PipelineFactory())
            {
                var pipe = factory.Create();
                var pipeWriter = factory.Create();
                var state = new ConnectionState(_listener);
                var recordHandler = new RecordProcessor(state);
                state.WriteKey = bKey;
                var buff = pipe.Alloc();
                var buffWrite = pipeWriter.Alloc();
                buffWrite.Write(plainText);
                var reader = buffWrite.AsReadableBuffer();
                recordHandler.WriteRecord(ref buff, (RecordType)plainText[0], reader.Slice(5));
                var result = buff.AsReadableBuffer().ToArray();
                Assert.Equal<byte>(message2, result);
                buff.FlushAsync().Wait();
            }
        }
    }
}