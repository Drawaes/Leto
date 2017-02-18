using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Leto.Tls13.Internal
{
    internal class ThreadScheduler : IScheduler, IDisposable
    {
        private BlockingCollection<Action> _work = new BlockingCollection<Action>();

        public System.Threading.Tasks.Task Thread { get; }

        public ThreadScheduler()
        {
            Thread = new Task(Work,TaskCreationOptions.LongRunning);
            Thread.Start();
        }

        public void Schedule(Action action)
        {
            _work.Add(action);
        }

        private void Work()
        {
            foreach (var callback in _work.GetConsumingEnumerable())
            {
                callback();
            }
        }

        public void Dispose()
        {
            _work.CompleteAdding();
        }
    }
}
