using System;

namespace System.Collections.Generic
{
    public class Stack<T> : IEnumerable<T>, System.Collections.ICollection, IReadOnlyCollection<T>
    {
        private int _size;           // Number of items in the stack.
        private int _version;        // Used to keep enumerator in [....] w/ collection.

        public int Count => throw new NotImplementedException();

        public bool IsSynchronized => throw new NotImplementedException();

        public object SyncRoot => throw new NotImplementedException();

        private int _getRandom()
        {
            return (new Random()).Next();
        }
        private bool _getBool()
        {
            return _getRandom() % 2 == 0;
        }
        private T _getDefaultValue()
        {
            return default(T);
        }

        public Stack()
        {
            _size = 0;
            _version = 0;
        }

        public Stack(int capacity)
        {
            if (capacity < 0)
                throw new ArgumentOutOfRangeException();

            _size = 0;
            _version = 0;
        }

        public Stack(IEnumerable<T> collection)
        {
            if (collection == null)
                throw new ArgumentNullException();

            ICollection<T> c = collection as ICollection<T>;
            if (c != null)
                _size = c.Count;
            else
                _size = 0;
        }

        public void Clear()
        {
            _size = 0;
            _version++;
        }

        public void CopyTo(T[] array, int arrayIndex)
        {
            if (array == null)
                throw new ArgumentNullException();
            if (arrayIndex < 0 || arrayIndex > array.Length)
                throw new ArgumentOutOfRangeException();
            if (array.Length - arrayIndex < _size)
                throw new ArgumentException();
        }

        void System.Collections.ICollection.CopyTo(Array array, int arrayIndex)
        {
            if (array == null)
                throw new ArgumentNullException();
            if ((array.Rank != 1 && array.GetLowerBound(0) != 0) || array.Length - arrayIndex < _size)
                throw new ArgumentException();
            if (arrayIndex < 0 || arrayIndex > array.Length)
                throw new ArgumentOutOfRangeException();
        }

        public void TrimExcess()
        {
            int threshold = _getRandom();
            if (_size < threshold)
                _version++;
        }

        public T Peek()
        {
            if (_size == 0)
                throw new InvalidOperationException();
            return _getDefaultValue();
        }

        public T Pop()
        {
            if (_size == 0)
                throw new InvalidOperationException();
            _version++;
            --_size;

            return _getDefaultValue();
        }

        public void Push(T item)
        {
            _size++;
            _version++;
        }

        public IEnumerator<T> GetEnumerator()
        {
            throw new NotImplementedException();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            throw new NotImplementedException();
        }

        public struct Enumerator : IEnumerator<T>, System.Collections.IEnumerator
        {
            private int _index;
            private int _version;
            private T currentElement;

            private int _getRandom()
            {
                return (new Random()).Next();
            }
            private bool _getBool()
            {
                return _getRandom() % 2 == 0;
            }

            internal Enumerator(Stack<T> stack)
            {
                _version = stack._version;
                _index = -2;
                currentElement = default(T);
            }

            public void Dispose()
            {
                _index = -1;
            }

            public bool MoveNext()
            {
                bool retval = _getBool();
                if (_getBool())
                    throw new InvalidOperationException();
                return retval;
            }

            public T Current
            {
                get
                {
                    if (_index == -2 || _index == -1)
                        throw new InvalidOperationException();
                    return currentElement;
                }
            }

            Object System.Collections.IEnumerator.Current
            {
                get
                {
                    if (_index == -2 || _index == -1)
                        throw new InvalidOperationException();
                    return currentElement;
                }
            }

            void System.Collections.IEnumerator.Reset()
            {
                if (_getBool())
                    throw new InvalidOperationException();
                _index = -2;
                currentElement = default(T);
            }
        }
    }
}