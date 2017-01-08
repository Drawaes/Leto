using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Leto.Tls13.State;

namespace Leto.Tls13.Handshake
{
    public class Finished
    {
        internal unsafe static void ReadClientFinished(ReadableBuffer messageBuffer, ConnectionState state)
        {
            messageBuffer = messageBuffer.Slice(4);
            var hashSize = state.HandshakeHash.HashSize;
            //We could let the equals function worry about this
            //however to avoid allocations we will copy a fragmented
            //client hash into the stack as it is small
            //however an attacker could send a large messge
            //and cause a stack overflow
            if (messageBuffer.Length != hashSize)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.decode_error);
            }
            //We have the client hash so we need to grab the client base key
            //and the hash up until now and make sure that the data is good
            var hash = stackalloc byte[hashSize];
            state.HandshakeHash.InterimHash(hash, hashSize);

            var key = state.KeySchedule.GenerateClientFinishedKey();
            fixed (byte* kPtr = key)
            {
                state.CryptoProvider.HashProvider.HmacData(state.CipherSuite.HashType, kPtr, key.Length, hash, hashSize, hash, hashSize);
            }
            Span<byte> clientHash;
            GCHandle handle = default(GCHandle);
            if(messageBuffer.IsSingleSpan)
            {
                var ptr = messageBuffer.First.GetPointer(out handle);
                clientHash = new Span<byte>(ptr, hashSize);
            }
            else
            {
                var bptr = stackalloc byte[hashSize];
                clientHash = new Span<byte>(bptr, hashSize);
                messageBuffer.CopyTo(clientHash);
            }
            try
            {
                if(!Internal.CompareFunctions.ConstantTimeEquals(clientHash, new Span<byte>(hash, hashSize)))
                {
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.bad_record_mac);
                }
                //So thats the end of the handshake. A number of house keeping items need to take place
                //such as changing the keys and scrubbing excess handshake data
                
            }
            finally
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }

        }
    }
}
