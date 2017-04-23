using System;
using System.Runtime.InteropServices;
using static Leto.EphemeralBuffers.Interop.Kernel32;

namespace Leto.EphemeralBuffers
{
    public sealed class EphemeralBufferPoolWindows : EphemeralBufferPool
    {
        private static object _lock = new object();
        
        public EphemeralBufferPoolWindows(int bufferSize, int bufferCount, bool allowWorkingSetIncrease = true) : base(bufferSize, bufferCount,allowWorkingSetIncrease)
        {
        }

        protected override IntPtr AllocateMemory(uint amountToAllocate)
        {
            var result = VirtualAlloc(IntPtr.Zero,(UIntPtr) amountToAllocate, MemOptions.MEM_COMMIT | MemOptions.MEM_RESERVE, PageOptions.PAGE_READWRITE);
            try
            {
                if (!VirtualLock(result, (UIntPtr)amountToAllocate))
                {
                    //We couldn't lock the memory
                    var error = (ExceptionHelper.WinErrors)Marshal.GetLastWin32Error();
                    if (_allowWorkingSetIncrease && error == ExceptionHelper.WinErrors.ERROR_WORKING_SET_QUOTA)
                    {
                        //We are going to try to increase the working set to allow us to lock the memory
                        lock (_lock)
                        {
                            var currentProcess = GetCurrentProcess();
                            if (!GetProcessWorkingSetSize(currentProcess, out IntPtr minimumWorkingSetSize, out IntPtr maximumWorkingSetSize))
                            {
                                error = (ExceptionHelper.WinErrors)Marshal.GetLastWin32Error();
                                ExceptionHelper.UnableToAllocateMemory(error);
                            }
                            var minSize = minimumWorkingSetSize.ToInt64() + amountToAllocate;
                            var maxSize = Math.Max(minSize, maximumWorkingSetSize.ToInt64());
                            if (!SetProcessWorkingSetSize(currentProcess, (IntPtr)minSize, (IntPtr)maxSize))
                            {
                                error = (ExceptionHelper.WinErrors)Marshal.GetLastWin32Error();
                                ExceptionHelper.UnableToAllocateMemory(error);
                            }
                            //We should have increase the working set so we can attempt to lock again
                            if (VirtualLock(result, (UIntPtr)amountToAllocate))
                            {
                                return result;
                            }
                            error = (ExceptionHelper.WinErrors)Marshal.GetLastWin32Error();
                        }
                    }
                    ExceptionHelper.UnableToAllocateMemory(error);
                }
                return result;
            }
            catch
            {
                //Attempt to free the memory we couldn't lock
                VirtualFree(result, (UIntPtr)amountToAllocate, 0x8000);
                throw;
            }
        }

        protected override int GetPageSize()
        {
            GetSystemInfo(out SYSTEM_INFO sysInfo);
            return sysInfo.dwPageSize;
        }

        protected override void FreeMemory(IntPtr pointer, uint amountToAllocate)
        {
            if (!VirtualFree(pointer, UIntPtr.Zero, 0x8000))
            {
                var error = (ExceptionHelper.WinErrors) Marshal.GetLastWin32Error();
                ExceptionHelper.UnableToFreeMemory(error);
            }
        }
    }
}
