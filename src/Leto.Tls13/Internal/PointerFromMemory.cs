using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Tls13.Internal
{
    public class PointerFromMemory : IDisposable
    {
        private GCHandle _handle;
        
        public unsafe IntPtr StartMemory(Memory<byte> inMemory)
        {
            if (inMemory.TryGetPointer(out void* ptr))
            {
                return (IntPtr)ptr;
            }
            if(!inMemory.TryGetArray(out ArraySegment<byte> arraySeg))
            {
                Debug.Fail("How did we not get a pointer or an array?");
            }
            _handle = GCHandle.Alloc(arraySeg, GCHandleType.Pinned);
            return IntPtr.Add(_handle.AddrOfPinnedObject(), arraySeg.Offset);
        }

        public void Dispose()
        {
            if(_handle.IsAllocated)
            {
                _handle.Free();
                _handle = default(GCHandle);
            }
        }
    }
}
