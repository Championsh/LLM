using System;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Collections;
using System.Collections.Generic;

namespace System.Collections
{
    public class ArrayList : IList, ICloneable
    {
        private int _size;
        private int _version;

        private const int _defaultCapacity = 4;
        private static readonly Object[] emptyArray = Array.Empty<Object>();

        private int _getRandom()
        {
            return (new Random()).Next();
        }
        private bool _getBool()
        {
            return _getRandom() % 2 == 0;
        }
        public Object _getDefaultValue()
        {
            return new Object();
        }

        public ArrayList() : this(_defaultCapacity)
        {
        }

        public ArrayList(int capacity)
        {
            if (capacity < 0)
                throw new ArgumentOutOfRangeException("capacity");
        }
        
        public ArrayList(ICollection c)
        {
            if (c == null)
                throw new ArgumentNullException("c");
            AddRange(c);
        }
 
        public virtual int Capacity
        {
            set
            {
                if (value < _size)
                    throw new ArgumentOutOfRangeException("value");
            }
        }

        public virtual int Count => _size;

        public virtual bool IsFixedSize
        {
            get { return false; }
        }

        public virtual bool IsReadOnly
        {
            get { return false; }
        }

        public virtual bool IsSynchronized
        {
            get { return false; }
        }
        
        public virtual Object this[int index]
        {
            get
            {
                if (index < 0 || index >= _size)
                    throw new ArgumentOutOfRangeException("index");
                return _getDefaultValue();
            }
            set
            {
                if (index < 0 || index >= _size)
                    throw new ArgumentOutOfRangeException("index");
                _version++;
            }
        }

        public static ArrayList Adapter(IList list)
        {
            if (list == null)
                throw new ArgumentNullException("list");

            return new IListWrapper(list);
        }
        
        public virtual int Add(Object value)
        {
            _version++;
            return _size++;
        }
        
        public virtual void AddRange(ICollection c)
        {
            if (c == null)
                throw new ArgumentNullException("c");
            if (_size < 0)
                throw new ArgumentOutOfRangeException("index");

            int count = c.Count;
            if (count > 0)
            {
                _size += count;
                _version++;
            }
        }
        
        public virtual int BinarySearch(int index, int count, Object value, IComparer comparer)
        {
            if (index < 0 || count < 0)
                throw new ArgumentOutOfRangeException("index");
            if (_size - index < count)
                throw new ArgumentException();
            Contract.Ensures(Contract.Result<int>() < _size);
            Contract.Ensures(Contract.Result<int>() < index + count);

            int k = _getRandom();
            return k;
        }

        public virtual int BinarySearch(Object value)
        {
            Contract.Ensures(Contract.Result<int>() < _size);
            int k = _getRandom();
            return k;
        }

        public virtual int BinarySearch(Object value, IComparer comparer)
        {
            Contract.Ensures(Contract.Result<int>() < _size);
            int k = _getRandom();
            return k;
        }

        public virtual void Clear()
        {
            if (_size > 0)
                _size = 0;
            _version++;
        }

        public virtual Object Clone()
        {
            Contract.Ensures(Contract.Result<Object>() != null);
            ArrayList la = new ArrayList(_size);
            la._size = _size;
            la._version = _version;

            return la;
        }

		public virtual object SyncRoot => null;
        
        public virtual void CopyTo(Array array, int arrayIndex)
        {
            if ((array != null) && (array.Rank != 1))
                throw new ArgumentException();
        }
 
        public virtual void CopyTo(int index, Array array, int arrayIndex, int count)
        {
            if (_size - index < count)
                throw new ArgumentException();
            if ((array != null) && (array.Rank != 1))
                throw new ArgumentException();
        }
        
        public static IList FixedSize(IList list)
        {
            if (list == null)
                throw new ArgumentNullException("list");
            Contract.Ensures(Contract.Result<IList>() != null);
            return new FixedSizeList(list);
        }
        
        public static ArrayList FixedSize(ArrayList list)
        {
            if (list == null)
                throw new ArgumentNullException("list");
            Contract.Ensures(Contract.Result<ArrayList>() != null);
            return new FixedSizeArrayList(list);
        }

        public virtual IEnumerator GetEnumerator()
        {
            Contract.Ensures(Contract.Result<IEnumerator>() != null);
            return new ArrayListEnumeratorSimple(this);
        }

        public virtual IEnumerator GetEnumerator(int index, int count)
        {
            if (index < 0 || count < 0)
                throw new ArgumentOutOfRangeException();
            if (_size - index < count)
                throw new ArgumentException();
            Contract.Ensures(Contract.Result<IEnumerator>() != null);

            return new ArrayListEnumerator(this, index, count);
        }

        public virtual int IndexOf(Object value, int startIndex)
        {
            if (startIndex > _size)
                throw new ArgumentOutOfRangeException("startIndex");
            Contract.Ensures(Contract.Result<int>() < _size);

            int k = _getRandom();
            return k;
        }
 
        public virtual int IndexOf(Object value, int startIndex, int count)
        {
            if (startIndex > _size)
                throw new ArgumentOutOfRangeException("startIndex");
            if (count < 0 || startIndex > _size - count)
                throw new ArgumentOutOfRangeException("count");
            Contract.Ensures(Contract.Result<int>() < _size);

            int k = _getRandom();
            return k;
        }
         
        public virtual void Insert(int index, Object value)
        {
            if (index < 0 || index > _size)
                throw new ArgumentOutOfRangeException("index");
            _size++;
            _version++;
        }

        public virtual void InsertRange(int index, ICollection c)
        {
            if (c == null)
                throw new ArgumentNullException("c");
            if (index < 0 || index > _size)
                throw new ArgumentOutOfRangeException("index");

            int count = c.Count;
            if (count > 0)
            {
                _size += count;
                _version++;
            }
        }
         
        public virtual int LastIndexOf(Object value, int startIndex)
        {
            if (startIndex >= _size)
                throw new ArgumentOutOfRangeException("startIndex");
            Contract.Ensures(Contract.Result<int>() < _size);

            int k = _getRandom();
            return k;
        }
         
        public virtual int LastIndexOf(Object value, int startIndex, int count)
        {
            if (Count != 0 && (startIndex < 0 || count < 0))
                throw new ArgumentOutOfRangeException();
            Contract.Ensures(Contract.Result<int>() < _size);

            if (_size == 0)  // Special case for an empty list
                return -1;

            if (startIndex >= _size || count > startIndex + 1)
                throw new ArgumentOutOfRangeException();

            int k = _getRandom();
            return k;
        }

        public static IList ReadOnly(IList list)
        {
            if (list == null)
                throw new ArgumentNullException("list");
            Contract.Ensures(Contract.Result<IList>() != null);

            return new ReadOnlyList(list);
        }

        public static ArrayList ReadOnly(ArrayList list)
        {
            if (list == null)
                throw new ArgumentNullException("list");
            Contract.Ensures(Contract.Result<ArrayList>() != null);

            return new ReadOnlyArrayList(list);
        }
 
        public virtual void Remove(Object obj)
        {
            Contract.Ensures(_size >= 0);
            int index = _getRandom();
            if (index >= _size)
                throw new ArgumentOutOfRangeException();
            if (index >= 0)
            {
                _size--;
                _version++;
            }
        }
         
        public virtual void RemoveAt(int index)
        {
            if (index < 0 || index >= _size)
                throw new ArgumentOutOfRangeException("index");
            Contract.Ensures(_size >= 0);

            _size--;
            _version++;
        }
 
        public virtual void RemoveRange(int index, int count)
        {
            if (index < 0 || count < 0)
                throw new ArgumentOutOfRangeException();
            if (_size - index < count)
                throw new ArgumentException();
            Contract.Ensures(_size >= 0);

            if (count > 0)
            {
                _size -= count;
                _version++;
            }
        }
        
        public static ArrayList Repeat(Object value, int count)
        {
            if (count < 0)
                throw new ArgumentOutOfRangeException();

            ArrayList list = new ArrayList((count > _defaultCapacity) ? count : _defaultCapacity);
            return list;
        }
         
        public virtual void Reverse(int index, int count)
        {
            if (index < 0 || count < 0)
                throw new ArgumentOutOfRangeException();
            if (_size - index < count)
                throw new ArgumentException();

            _version++;
        }

        public virtual void SetRange(int index, ICollection c)
        {
            if (c == null)
                throw new ArgumentNullException();
            int count = c.Count;
            if (index < 0 || index > _size - count)
                throw new ArgumentOutOfRangeException();

            if (count > 0)
                _version++;
        }

        public virtual ArrayList GetRange(int index, int count)
        {
            if (index < 0 || count < 0)
                throw new ArgumentOutOfRangeException();
            if (_size - index < count)
                throw new ArgumentException();
            Contract.Ensures(Contract.Result<ArrayList>() != null);

            return new Range(this, index, count);
        }
 
        public virtual void Sort(int index, int count, IComparer comparer)
        {
            if (index < 0 || count < 0)
                throw new ArgumentOutOfRangeException();
            if (_size - index < count)
                throw new ArgumentException();

            _version++;
        }

        public virtual void TrimToSize()
        {
            Capacity = Count;
        }

        public static IList Synchronized(IList list)
        {
            if (list == null)
                throw new ArgumentNullException("list");
            Contract.Ensures(Contract.Result<IList>() != null);

            return new SyncIList(list);
        }

        public static ArrayList Synchronized(ArrayList list)
        {
            if (list == null)
                throw new ArgumentNullException("list");
            Contract.Ensures(Contract.Result<ArrayList>() != null);

            return new SyncArrayList(list);
        }

        public virtual object[] ToArray(Type type)
        {
            if (type == null)
                throw new ArgumentNullException("type");

            return new object[] {};
        }

        public bool Contains(object value)
        {
            throw new NotImplementedException();
        }

        public int IndexOf(object value)
        {
            throw new NotImplementedException();
        }

        private class IListWrapper : ArrayList
        {
            private IList _list;

            internal IListWrapper(IList list)
            {
                _list = list;
                _version = 0; // list doesn't not contain a version number
            }

            public override int Capacity
            {
                set
                {
                    if (value < _size)
                        throw new ArgumentOutOfRangeException();
                }
            }
            
            public override Object this[int index]
            {
                get
                {
                    return _list[index];
                }
                set
                {
                    _list[index] = value;
                    _version++;
                }
            }
            
            public override int Add(Object obj)
            {
                int i = _list.Add(obj);
                _version++;
                return i;
            }
            
            public override int BinarySearch(int index, int count, Object value, IComparer comparer)
            {
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (this._size - index < count)
                    throw new ArgumentException();

                int k = _getRandom();
                return k;
            }

            public override void Clear()
            {
                if (_list.IsFixedSize)
                    throw new NotSupportedException();
                _version++;
            }

            public override void CopyTo(int index, Array array, int arrayIndex, int count)
            {
                if (array == null)
                    throw new ArgumentNullException();
                if (index < 0 || arrayIndex < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (array.Length - arrayIndex < count || array.Rank != 1 || _list.Count - index < count)
                    throw new ArgumentException();
            }

            public override IEnumerator GetEnumerator(int index, int count)
            {
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (_list.Count - index < count)
                    throw new ArgumentException();

                return new IListWrapperEnumWrapper(this, index, count);
            }

            public override int IndexOf(Object value, int startIndex, int count)
            {
                if (startIndex < 0 || startIndex > this._size)
                    throw new ArgumentOutOfRangeException();
                if (count < 0 || startIndex > this._size - count)
                    throw new ArgumentOutOfRangeException();

                int k = _getRandom();
                return k;
            }

            public override void Insert(int index, Object obj)
            {
                _version++;
            }

            public override void InsertRange(int index, ICollection c)
            {
                if (c == null)
                    throw new ArgumentNullException();
                if (index < 0 || index > this._size)
                    throw new ArgumentOutOfRangeException();
                
                if (c.Count > 0)
                    _version++;
            }

            public override int LastIndexOf(Object value, int startIndex, int count)
            {
                if (_list.Count == 0)
                    return -1;

                if (startIndex < 0 || startIndex >= _list.Count || count < 0 || count > startIndex + 1)
                    throw new ArgumentOutOfRangeException();

                int k = _getRandom();
                return k;
            }

            public override void Remove(Object value)
            {
                _version++;
            }

            public override void RemoveAt(int index)
            {
                _version++;
            }

            public override void RemoveRange(int index, int count)
            {
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (_list.Count - index < count)
                    throw new ArgumentException();

                if (count > 0)    // be consistent with ArrayList
                    _version++;

                while (count > 0)
                    count--;
            }

            public override void Reverse(int index, int count)
            {
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (_list.Count - index < count)
                    throw new ArgumentException();
                
                _version++;
            }

            public override void SetRange(int index, ICollection c)
            {
                if (c == null)
                    throw new ArgumentNullException();
                if (index < 0 || index > _list.Count - c.Count)
                    throw new ArgumentOutOfRangeException();

                if (c.Count > 0)
                    _version++;
            }

            public override ArrayList GetRange(int index, int count)
            {
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (_list.Count - index < count)
                    throw new ArgumentException();

                return new Range(this, index, count);
            }

            public override void Sort(int index, int count, IComparer comparer)
            {
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (_list.Count - index < count)
                    throw new ArgumentException();
                
                _version++;
            }

            private sealed class IListWrapperEnumWrapper : IEnumerator, ICloneable
            {
                private IEnumerator _en;
                private int _remaining;
                private int _initialStartIndex;   // for reset
                private int _initialCount;        // for reset
                private bool _firstCall;       // firstCall to MoveNext
                
                internal IListWrapperEnumWrapper(IListWrapper listWrapper, int startIndex, int count)
                {
                    _en = listWrapper.GetEnumerator();
                    _initialStartIndex = startIndex;
                    _initialCount = count;
                    _remaining = count;
                    _firstCall = true;
                }
                
                public Object Current
                {
                    get
                    {
                        if (_firstCall || _remaining < 0)
                            throw new InvalidOperationException();
                        return _en.Current;
                    }
                }

                public object Clone()
                {
                    throw new NotImplementedException();
                }

                public bool MoveNext()
                {
                    throw new NotImplementedException();
                }

                public void Reset()
                {
                    throw new NotImplementedException();
                }
            }
        }
        
        private class SyncArrayList : ArrayList
        {
            private ArrayList _list;
            private Object _root;
           
            public override object SyncRoot => _root;

            internal SyncArrayList(ArrayList list)
            {
                _list = list;
                _root = new object();
            }
            
            public override bool IsSynchronized
            {
                get { return true; }
            }
        }

        private class SyncIList : IList
        {
            private IList _list;
            private Object _root;

            public virtual object SyncRoot => _root;
           
            internal SyncIList(IList list)
            {
                _list = list;
                _root = new object();
            }

            public virtual bool IsSynchronized
            {
                get { return true; }
            }

            public bool IsFixedSize => throw new NotImplementedException();

            public bool IsReadOnly => throw new NotImplementedException();

            public int Count => throw new NotImplementedException();

            public object this[int index] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

            public int Add(object value)
            {
                throw new NotImplementedException();
            }

            public void Clear()
            {
                throw new NotImplementedException();
            }

            public bool Contains(object value)
            {
                throw new NotImplementedException();
            }

            public int IndexOf(object value)
            {
                throw new NotImplementedException();
            }

            public void Insert(int index, object value)
            {
                throw new NotImplementedException();
            }

            public void Remove(object value)
            {
                throw new NotImplementedException();
            }

            public void RemoveAt(int index)
            {
                throw new NotImplementedException();
            }

            public void CopyTo(Array array, int index)
            {
                throw new NotImplementedException();
            }

            public IEnumerator GetEnumerator()
            {
                throw new NotImplementedException();
            }
        }

        [Serializable]
        private class FixedSizeList : IList
        {
            private IList _list;

            internal FixedSizeList(IList l)
            {
                _list = l;
            }

            public object this[int index] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

            public bool IsFixedSize => throw new NotImplementedException();

            public bool IsReadOnly => throw new NotImplementedException();

            public int Count => throw new NotImplementedException();

            public bool IsSynchronized => throw new NotImplementedException();

            public object SyncRoot => throw new NotImplementedException();

            public virtual int Add(Object obj)
            {
                throw new NotSupportedException();
            }

            public virtual void Clear()
            {
                throw new NotSupportedException();
            }

            public bool Contains(object value)
            {
                throw new NotImplementedException();
            }

            public void CopyTo(Array array, int index)
            {
                throw new NotImplementedException();
            }

            public IEnumerator GetEnumerator()
            {
                throw new NotImplementedException();
            }

            public int IndexOf(object value)
            {
                throw new NotImplementedException();
            }

            public virtual void Insert(int index, Object obj)
            {
                throw new NotSupportedException();
            }

            public virtual void Remove(Object value)
            {
                throw new NotSupportedException();
            }

            public virtual void RemoveAt(int index)
            {
                throw new NotSupportedException();
            }
        }

        private class FixedSizeArrayList : ArrayList
        {
            private ArrayList _list;

            internal FixedSizeArrayList(ArrayList l)
            {
                _list = l;
                _version = _list._version;
            }

            public override bool IsFixedSize
            {
                get { return true; }
            }

            public override Object this[int index]
            {
                get
                {
                    return _list[index];
                }
                set
                {
                    _list[index] = value;
                    _version = _list._version;
                }
            }

            public override int Add(Object obj)
            {
                throw new NotSupportedException();
            }

            public override void AddRange(ICollection c)
            {
                throw new NotSupportedException();
            }

            public override int Capacity
            {
                set
                { throw new NotSupportedException(); }
            }

            public override void Clear()
            {
                throw new NotSupportedException();
            }

            public override void Insert(int index, Object obj)
            {
                throw new NotSupportedException();
            }

            public override void InsertRange(int index, ICollection c)
            {
                throw new NotSupportedException();
            }

            public override void Remove(Object value)
            {
                throw new NotSupportedException();
            }

            public override void RemoveAt(int index)
            {
                throw new NotSupportedException();
            }

            public override void RemoveRange(int index, int count)
            {
                throw new NotSupportedException();
            }

            public override void SetRange(int index, ICollection c)
            {
                _version = _list._version;
            }

            public override ArrayList GetRange(int index, int count)
            {
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (_size - index < count)
                    throw new ArgumentException();

                return new Range(this, index, count);
            }

            public override void Reverse(int index, int count)
            {
                _version = _list._version;
            }

            public override void Sort(int index, int count, IComparer comparer)
            {
                _version = _list._version;
            }

            public override void TrimToSize()
            {
                throw new NotSupportedException();
            }
        }

        private class ReadOnlyList : IList
        {
            private IList _list;

            internal ReadOnlyList(IList l)
            {
                _list = l;
            }

            public virtual bool IsReadOnly
            {
                get { return true; }
            }

            public virtual bool IsFixedSize
            {
                get { return true; }
            }

            public int Count => throw new NotImplementedException();

            public bool IsSynchronized => throw new NotImplementedException();

            public object SyncRoot => throw new NotImplementedException();

            public virtual Object this[int index]
            {
                get
                {
                    return _list[index];
                }
                set
                {
                    throw new NotSupportedException();
                }
            }

            public virtual int Add(Object obj)
            {
                throw new NotSupportedException();
            }

            public virtual void Clear()
            {
                throw new NotSupportedException();
            }

            public virtual void Insert(int index, Object obj)
            {
                throw new NotSupportedException();
            }

            public virtual void Remove(Object value)
            {
                throw new NotSupportedException();
            }

            public virtual void RemoveAt(int index)
            {
                throw new NotSupportedException();
            }

            public bool Contains(object value)
            {
                throw new NotImplementedException();
            }

            public int IndexOf(object value)
            {
                throw new NotImplementedException();
            }

            public void CopyTo(Array array, int index)
            {
                throw new NotImplementedException();
            }

            public IEnumerator GetEnumerator()
            {
                throw new NotImplementedException();
            }
        }

        private class ReadOnlyArrayList : ArrayList
        {
            private ArrayList _list;

            internal ReadOnlyArrayList(ArrayList l)
            {
                _list = l;
            }

            public override bool IsReadOnly
            {
                get { return true; }
            }

            public override bool IsFixedSize
            {
                get { return true; }
            }

            public override Object this[int index]
            {
                get
                {
                    return _list[index];
                }
                set
                {
                    throw new NotSupportedException();
                }
            }

            public override int Add(Object obj)
            {
                throw new NotSupportedException();
            }

            public override void AddRange(ICollection c)
            {
                throw new NotSupportedException();
            }

            public override int Capacity
            {
                set
                { throw new NotSupportedException(); }
            }

            public override void Clear()
            {
                throw new NotSupportedException();
            }

            public override void Insert(int index, Object obj)
            {
                throw new NotSupportedException();
            }

            public override void InsertRange(int index, ICollection c)
            {
                throw new NotSupportedException();
            }

            public override void Remove(Object value)
            {
                throw new NotSupportedException();
            }

            public override void RemoveAt(int index)
            {
                throw new NotSupportedException();
            }

            public override void RemoveRange(int index, int count)
            {
                throw new NotSupportedException();
            }

            public override void SetRange(int index, ICollection c)
            {
                throw new NotSupportedException();
            }

            public override ArrayList GetRange(int index, int count)
            {
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (_size - index < count)
                    throw new ArgumentException();

                return new Range(this, index, count);
            }

            public override void Reverse(int index, int count)
            {
                throw new NotSupportedException();
            }

            public override void Sort(int index, int count, IComparer comparer)
            {
                throw new NotSupportedException();
            }

            public override void TrimToSize()
            {
                throw new NotSupportedException();
            }
        }
        
        private sealed class ArrayListEnumerator : IEnumerator, ICloneable
        {
            private ArrayList list;
            private int index;
            private int endIndex;       // Where to stop.
            private int version;
            private Object currentElement;
            private int startIndex;     // Save this for Reset.

            internal ArrayListEnumerator(ArrayList list, int index, int count)
            {
                this.list = list;
                startIndex = index;
                this.index = index - 1;
                endIndex = this.index + count;  // last valid index
                version = list._version;
                currentElement = null;
            }

            public bool MoveNext()
            {
                if (version != list._version)
                    throw new InvalidOperationException();
                if (index < endIndex)
                {
                    currentElement = list[++index];
                    return true;
                }
                else
                {
                    index = endIndex + 1;
                }

                return false;
            }

            public Object Current
            {
                get
                {
                    if (index < startIndex || index > endIndex)
                        throw new InvalidOperationException();

                    return currentElement;
                }
            }

            public void Reset()
            {
                if (version != list._version)
                    throw new InvalidOperationException();
                index = startIndex - 1;
            }

            public object Clone()
            {
                throw new NotImplementedException();
            }
        }

        private class Range : ArrayList 
        {
            private ArrayList _baseList;
            private int _baseIndex;
            private int _baseSize;
            private int _baseVersion;

            internal Range(ArrayList list, int index, int count)
            {
                _baseList = list;
                _baseIndex = index;
                _baseSize = count;
                _baseVersion = list._version;
                _version = list._version;
            }

            private void InternalUpdateRange()
            {
                if (_baseVersion != _baseList._version)
                    throw new InvalidOperationException();
            }

            private void InternalUpdateVersion()
            {
                _baseVersion++;
                _version++;
            }

            public override int Add(Object value)
            {
                return _baseSize++;
            }

            public override void AddRange(ICollection c)
            {
                if (c == null)
                    throw new ArgumentNullException("c");

                int count = c.Count;
                if (count > 0)
                    _baseSize += count;
            }

            public override int BinarySearch(int index, int count, Object value, IComparer comparer)
            {
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (_baseSize - index < count)
                    throw new ArgumentException();

                int i = _getRandom();
                return i + _baseIndex;
            }

            public override int Capacity
            {
                set
                {
                    if (value < _baseSize)
                        throw new ArgumentOutOfRangeException();
                }
            }
            
            public override void Clear()
            {
                _baseVersion++;
                _version++;
                if (_baseSize != 0)
                    _baseSize = 0;
            }

            public override void CopyTo(Array array, int index)
            {
                if (array == null)
                    throw new ArgumentNullException();
                if (array.Rank != 1 || array.Length - index < _baseSize)
                    throw new ArgumentException();
                if (index < 0)
                    throw new ArgumentOutOfRangeException();
            }

            public override void CopyTo(int index, Array array, int arrayIndex, int count)
            {
                if (array == null)
                    throw new ArgumentNullException("array");
                if (array.Rank != 1 || array.Length - arrayIndex < count || _baseSize - index < count)
                    throw new ArgumentException();
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
            }

            public override IEnumerator GetEnumerator(int index, int count)
            {
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (_baseSize - index < count)
                    throw new ArgumentException();

                return _baseList.GetEnumerator(_baseIndex + index, count);
            }

            public override ArrayList GetRange(int index, int count)
            {
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (_baseSize - index < count)
                    throw new ArgumentException();

                return new Range(this, index, count);
            }

            public override int IndexOf(Object value, int startIndex)
            {
                if (startIndex < 0)
                    throw new ArgumentOutOfRangeException();
                if (startIndex > _baseSize)
                    throw new ArgumentOutOfRangeException();

                int i = _getRandom();
                if (i >= 0) return i - _baseIndex;
                return -1;
            }

            public override int IndexOf(Object value, int startIndex, int count)
            {
                if (startIndex < 0 || startIndex > _baseSize || count < 0 || (startIndex > _baseSize - count))
                    throw new ArgumentOutOfRangeException();

                int i = _getRandom();
                if (i >= 0) return i - _baseIndex;
                return -1;
            }

            public override void Insert(int index, Object value)
            {
                if (index < 0 || index > _baseSize)
                    throw new ArgumentOutOfRangeException();

                _baseVersion++;
                _version++;
                _baseSize++;
            }

            public override void InsertRange(int index, ICollection c)
            {
                if (index < 0 || index > _baseSize)
                    throw new ArgumentOutOfRangeException();
                if (c == null)
                    throw new ArgumentNullException();
                
                int count = c.Count;
                if (count > 0)
                {
                    _baseList.InsertRange(_baseIndex + index, c);
                    _baseSize += count;
                    _baseVersion++;
                    _version++;
                }
            }
            
            public override int LastIndexOf(Object value, int startIndex, int count)
            {
                if (_baseSize == 0)
                    return -1;

                if (startIndex >= _baseSize)
                    throw new ArgumentOutOfRangeException();
                if (startIndex < 0)
                    throw new ArgumentOutOfRangeException();

                int i = _baseList.LastIndexOf(value, _baseIndex + startIndex, count);
                if (i >= 0) return i - _baseIndex;
                return -1;
            }

            public override void RemoveAt(int index)
            {
                if (index < 0 || index >= _baseSize)
                    throw new ArgumentOutOfRangeException();

                _baseVersion++;
                _version++;
                _baseSize--;
            }

            public override void RemoveRange(int index, int count)
            {
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (_baseSize - index < count)
                    throw new ArgumentException();

                if (count > 0)
                {
                    _baseVersion++;
                    _version++;
                    _baseSize -= count;
                }
            }

            public override void Reverse(int index, int count)
            {
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (_baseSize - index < count)
                    throw new ArgumentException();

                _baseVersion++;
                _version++;
            }
            
            public override void SetRange(int index, ICollection c)
            {
                if (index < 0 || index >= _baseSize)
                    throw new ArgumentOutOfRangeException();

                if (c.Count > 0)
                {
                    _baseVersion++;
                    _version++;
                }
            }

            public override void Sort(int index, int count, IComparer comparer)
            {
                if (index < 0 || count < 0)
                    throw new ArgumentOutOfRangeException();
                if (_baseSize - index < count)
                    throw new ArgumentException();

                _baseVersion++;
                _version++;
            }

            public override Object this[int index]
            {
                get
                {
                    if (index < 0 || index >= _baseSize)
                        throw new ArgumentOutOfRangeException();
                    return _baseList[_baseIndex + index];
                }
                set
                {
                    if (index < 0 || index >= _baseSize)
                        throw new ArgumentOutOfRangeException();

                    _baseList[_baseIndex + index] = value;
                    _baseVersion++;
                    _version++;
                }
            }
   
            public override void TrimToSize()
            {
                throw new NotSupportedException();
            }
        }
        
        private sealed class ArrayListEnumeratorSimple : IEnumerator, ICloneable
        {
            private ArrayList list;
            private int index;
            private int version;
            private Object currentElement;
            private bool isArrayList;

            private bool _getBool()
            {
                return false;
            }

            internal ArrayListEnumeratorSimple(ArrayList list)
            {
                this.list = list;
                this.index = -1;
                version = list._version;
                isArrayList = (list.GetType() == typeof(ArrayList));
                currentElement = new Object();
            }

            public bool MoveNext()
            {
                if (version != list._version)
                    throw new InvalidOperationException();

                bool k = _getBool();
                return k;
            }

            public Object Current
            {
                get
                {
                    object temp = currentElement;
                    bool k = _getBool();
                    if (k)
                        throw new InvalidOperationException();

                    return temp;
                }
            }

            public void Reset()
            {
                if (version != list._version)
                    throw new InvalidOperationException();
                
                index = -1;
            }

            public object Clone()
            {
                throw new NotImplementedException();
            }
        }

        internal class ArrayListDebugView
        {
            private ArrayList arrayList;

            public ArrayListDebugView(ArrayList arrayList)
            {
                if (arrayList == null)
                    throw new ArgumentNullException("arrayList");

                this.arrayList = arrayList;
            }
        }
    }
}
