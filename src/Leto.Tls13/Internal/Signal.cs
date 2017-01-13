using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace Leto.Tls13.Internal
{
    public class Signal : ICriticalNotifyCompletion
    {
        private readonly ContinuationMode _continuationMode;

        private Action _continuation;
        private static readonly Action _completedSentinel = delegate { };

        internal Signal(ContinuationMode continuationMode = ContinuationMode.Synchronous)
        {
            _continuationMode = continuationMode;
        }

        public bool IsCompleted => ReferenceEquals(_completedSentinel, Volatile.Read(ref _continuation));

        private object SyncLock => this;

        public Signal GetAwaiter() => this;

        public void GetResult() { }

        public void UnsafeOnCompleted(Action continuation) => OnCompleted(continuation);

        public void OnCompleted(Action continuation)
        {
            if (continuation != null)
            {
                var oldValue = Interlocked.CompareExchange(ref _continuation, continuation, null);

                if (ReferenceEquals(oldValue, _completedSentinel))
                {
                    // already complete; calback sync
                    continuation.Invoke();
                }
                else if (oldValue != null)
                {
                    ThrowMultipleCallbacksNotSupported();
                }
            }
        }
        private static void ThrowMultipleCallbacksNotSupported()
        {
            throw new NotSupportedException("Multiple callbacks via Signal.OnCompleted are not supported");
        }


        public void Reset()
        {
            Volatile.Write(ref _continuation, null);
        }

        public void Set()
        {
            Action continuation = Interlocked.Exchange(ref _continuation, _completedSentinel);

            if (continuation != null && !ReferenceEquals(continuation, _completedSentinel))
            {
                switch (_continuationMode)
                {
                    case ContinuationMode.Synchronous:
                        continuation.Invoke();
                        break;
                    default:
                        break;
                }
            }
        }

        // utility method for people who don't feel comfortable with `await obj;` and prefer `await obj.WaitAsync();`
        internal Signal WaitAsync() => this;

        internal enum ContinuationMode
        {
            Synchronous,
            ThreadPool,
            // TODO: sync-context? but if so: whose? the .Current at creation? at SetResult?
        }
    }
}
