using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Tls13.Internal
{
    public unsafe class PointerFromMemory:IDisposable
    {
        private byte* _pointer;

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public void ProcessMemory(Memory<byte> inMemory)
        {
           
        }
    }
}
