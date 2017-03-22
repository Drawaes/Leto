using Leto.Hashes;
using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Windows
{
    public class WindowsHash : IHash
    {
        public int HashSize => throw new NotImplementedException();

        public HashType HashType => throw new NotImplementedException();

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public int FinishHash(Span<byte> output)
        {
            throw new NotImplementedException();
        }

        public void HashData(ReadOnlySpan<byte> data)
        {
            throw new NotImplementedException();
        }

        public int InterimHash(Span<byte> output)
        {
            throw new NotImplementedException();
        }
    }
}
