using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;

namespace Leto.Tls13.Hash
{
    public interface IHashInstance : IDisposable
    {
        int HashSize { get; }
        unsafe void InterimHash(byte* hash, int hashSize);
        unsafe void HashData(byte* message, int messageLength);
    }
}