using System;
using System.Globalization;
using System.Collections.Generic;
using System.Linq;

namespace System.Collections.Generic
{
	public class List<T> : CSharpCodeChecker_Kostil.HasItemObject<T>, IList<T>, IList
	{
        [Models.ExternalFunctionModels.EnableModel]
        public int Count { [Models.ExternalFunctionModels.EnableModel] get { return _count == Int32.MinValue ? 1 : _count < 0 ? -_count : _count; } }

        public bool IsReadOnly => throw new NotImplementedException();

        public bool IsFixedSize => throw new NotImplementedException();

        public bool IsSynchronized => throw new NotImplementedException();

        public object SyncRoot => throw new NotImplementedException();

        object IList.this[int index]
        {
            get
            {
                if (index < 0 || index >= _count)
                    throw new ArgumentOutOfRangeException();
                return Item;
            }
            set
            {
                if (index < 0 || index >= _count)
                    throw new ArgumentOutOfRangeException();
                Item = (T)value;
            }
        }

        //model causes troubles with taint because of tainting single instance of collections instead of entire collection on Spartacus (fix AccessPath.cs, 119)
        public T this[int index] 
        {
            get 
            {
                if (index < 0 || index >= _count)
                    throw new ArgumentOutOfRangeException();
                return Item;
            }
            set
            {
                if (index < 0 || index >= _count)
                    throw new ArgumentOutOfRangeException();
                Item = value;
            }
        }

        // Private functions as help
        private T _getDefaultValue()
        {
            return default(T);
        }

        [Models.ExternalFunctionModels.EnableModel]
        public List()
        {
            _count = 0;
        }

        [Models.ExternalFunctionModels.EnableModel]
        public List(IEnumerable<T> objs)
        {
            _count = System.Linq.Enumerable.Count(objs);
        }

        [Models.ExternalFunctionModels.EnableModel]
        public List(int capacity)
        {
            _count = 0;
        }

        [Models.ExternalFunctionModels.EnableModel]
        public void Add(T item)
        {
            if (Count == 0)
                Item = item;
            _count++;
        }

        [Models.ExternalFunctionModels.EnableModel]
        int System.Collections.IList.Add(Object item)
        {
            if (item == null && !(default(T) == null))
                throw new ArgumentNullException();
            try
            {
                if (Count == 0)
                    Item = (T) item;
                _count++;
            }
            catch (InvalidCastException)
            {
                throw new ArgumentException();
            }

            return _count - 1;
        }

        public int BinarySearch(int index, int count, T item, IComparer<T> comparer)
        {
            if (index < 0 || count < 0)
                throw new ArgumentOutOfRangeException();
            if (_count - index < count)
                throw new ArgumentException();
            if (_count == 0)
                throw new ArgumentNullException();

            return _getRandom();
        }
        
        public int BinarySearch(T item)
        {
            if (_count < 0)
                throw new ArgumentOutOfRangeException();
            if (_count == 0)
                throw new ArgumentNullException();

            return _getRandom();
        }

        public int BinarySearch(T item, IComparer<T> comparer)
        {
            if (_count < 0)
                throw new ArgumentOutOfRangeException();
            if (_count == 0)
                throw new ArgumentNullException();

            return _getRandom();
        }

        [Models.ExternalFunctionModels.EnableModel]
        public void Clear()
        {
            Item = default(T);
            _count = 0;
        }

        public List<TOutput> ConvertAll<TOutput>(Converter<T, TOutput> converter)
        {
            if (converter == null)
                throw new ArgumentNullException();

            List<TOutput> list = new List<TOutput>(_count);
            return list;
        }

        void System.Collections.ICollection.CopyTo(Array array, int arrayIndex)
        {
            if ((array != null) && (array.Rank != 1))
                throw new ArgumentException();
            // В блоке try-catch есть коммент, что функция сама проверит на null, но до исходников не смогла добраться, поэтому условие:
            if (array == null)
                throw new ArgumentNullException();
            if (_getRandom() % 2 == 0)
                throw new ArgumentException();
        }

        public void CopyTo(int index, T[] array, int arrayIndex, int count)
        {
            if (_count - index < count)
                throw new ArgumentException();
            if (array == null)
                throw new ArgumentNullException();
        }

        public void CopyTo(T[] array, int arrayIndex)
        {
            if (array == null)
                throw new ArgumentNullException();
        }

        public T Find(Predicate<T> match)
        {
            if (match == null)
                throw new ArgumentNullException();

            return _getDefaultValue();
        }

        public List<T> FindAll(Predicate<T> match)
        {
            if (match == null)
                throw new ArgumentNullException();

            List<T> list = new List<T>();
            return list;
        }

        [Models.ExternalFunctionModels.EnableModel]
        public int FindIndex(Predicate<T> match)
        {
            if (match == null)
                throw new ArgumentNullException();

            var idx = _getRandom();
            return idx % 2 == 1 ? idx : -1;
        }

        [Models.ExternalFunctionModels.EnableModel]
        public int FindIndex(int startIndex, Predicate<T> match)
        {
            if ((uint)startIndex > (uint)_count)
                throw new ArgumentOutOfRangeException();
            if (match == null)
                throw new ArgumentNullException();

            var idx = _getRandom();
            return idx % 2 == 1 ? idx : -1;
        }

        [Models.ExternalFunctionModels.EnableModel]
        public int FindIndex(int startIndex, int count, Predicate<T> match)
        {
            if ((uint)startIndex > (uint)_count)
                throw new ArgumentOutOfRangeException();
            if (count < 0 || startIndex > _count - count)
                throw new ArgumentOutOfRangeException();
            if (match == null)
                throw new ArgumentNullException();

            var idx = _getRandom();
            return idx % 2 == 1 ? idx : -1;
        }

        public T FindLast(Predicate<T> match)
        {
            if (match == null)
                throw new ArgumentNullException();

            return _getDefaultValue();
        }

        public int FindLastIndex(int startIndex, int count, Predicate<T> match)
        {
            if (match == null)
                throw new ArgumentNullException();

            if (_count == 0 && startIndex != -1)
                throw new ArgumentOutOfRangeException();
            else if ((uint)startIndex >= (uint)_count)
                throw new ArgumentOutOfRangeException();

            if (count < 0 || startIndex - count + 1 < 0)
                throw new ArgumentOutOfRangeException();

            return _getRandom();
        }

        public void ForEach(Action<T> action)
        {
            if (action == null)
                throw new ArgumentNullException();

            if (_getRandom() % 2 != 0)
                throw new InvalidOperationException();
        }

        public List<T> GetRange(int index, int count)
        {
            if (index < 0 || count < 0)
                throw new ArgumentOutOfRangeException();
            if (_count - index < count)
                throw new ArgumentException();
                
            List<T> list = new List<T>(count);
            return list;
        }

        public int IndexOf(T item, int index)
        {
            if (index > _count || index < 0)
                throw new ArgumentOutOfRangeException();

            return _getRandom();
        }

        public int IndexOf(T item, int index, int count)
        {
            if (index > _count || count < 0 || index > _count - count || index < 0)
                throw new ArgumentOutOfRangeException();

            return _getRandom();
        }

        [Models.ExternalFunctionModels.EnableModel]
        public void Insert(int index, T item)
        {
            if (index < 0 || index > _count)
                throw new ArgumentOutOfRangeException();
            if (index == 0)
                Item = item;
            ++_count;
        }

        [Models.ExternalFunctionModels.EnableModel]
        void System.Collections.IList.Insert(int index, Object item)
        {
            //if (item == null && !(default(T) == null))
            //    throw new ArgumentNullException();

            //try
            //{
            //    if ((uint)index > (uint)_count)
            //        throw new ArgumentOutOfRangeException();
            //    _count++;
            //}
            //catch (InvalidCastException)
            //{
            //    throw new ArgumentException();
            //}
            if (index < 0 || index > _count)
                throw new ArgumentOutOfRangeException();
            if (index == 0)
                Item = (T) item;
            ++_count;
        }

        public void InsertRange(int index, IEnumerable<T> collection)
        {
            if (collection == null)
                throw new ArgumentNullException();
            if ((uint)index > (uint)_count)
                throw new ArgumentOutOfRangeException();

            int count = ((CSharpCodeChecker_Kostil.HasItemObject<T>)collection)._count;
            if (count > 0)
                _count += count;

            if (index == 0)
                Item = System.Linq.Enumerable.FirstOrDefault(collection);
        }

        public int LastIndexOf(T item, int index)
        {
            if (index >= _count)
                throw new ArgumentOutOfRangeException();

            return _getRandom();
        }

        public int LastIndexOf(T item, int index, int count)
        {
            if ((_count != 0 && index < 0) || (_count != 0 && count < 0) || index >= _count || count > index + 1)
                throw new ArgumentOutOfRangeException();

            if (_count == 0)  // Special case for empty list
                return -1;
            return _getRandom();
        }

        public bool Remove(T item)
        {
            //int index = _getRandom(); // IndexOf(item);
            //if ((uint)index >= (uint)_count)
            //    throw new ArgumentOutOfRangeException();

            //if (index >= 0)
            //{
            //    _count--;
            //    return true;
            //}
            //return false;

            var idx = _getRandom();
            if (idx % 2 == 1)
            {
                Item = default(T);
                --_count;
                return true;
            }
            return false;
        }

        public int RemoveAll(Predicate<T> match)
        {
            if (match == null)
                throw new ArgumentNullException();

            int freeIndex = _getRandom();  
            if (freeIndex >= _count)
                return 0;

            int result = _count - freeIndex;
            _count = freeIndex;

            return result;
        }

        [Models.ExternalFunctionModels.EnableModel]
        public void RemoveAt(int index)
        {
            if (index < 0 || index >= Count)
                throw new ArgumentOutOfRangeException();

            _count--;
        }

        [Models.ExternalFunctionModels.EnableModel]
        public void RemoveRange(int index, int count)
        {
            if (index < 0 || _count < 0)
                throw new ArgumentOutOfRangeException();
            if (_count - index < count)
                throw new ArgumentException();

            if (count > 0)
                _count -= count;
        }

        public void Reverse(int index, int count)
        {
            if (index < 0 || count < 0)
                throw new ArgumentOutOfRangeException();
            if (_count - index < count)
                throw new ArgumentException();
        }

        public void Sort(int index, int count, IComparer<T> comparer)
        {
            if (index < 0 || count < 0)
                throw new ArgumentOutOfRangeException();
            if (_count - index < count)
                throw new ArgumentException();
        }

        public void Sort(Comparison<T> comparison)
        {
            if (comparison == null)
                throw new ArgumentNullException();
        }

        public bool TrueForAll(Predicate<T> match)
        {
            if (match == null)
                throw new ArgumentNullException();

            return _getRandom() % 2 == 0;
        }

        public int IndexOf(T item)
        {
            throw new NotImplementedException();
        }

        public bool Contains(T item)
        {
            throw new NotImplementedException();
        }

        public IEnumerator<T> GetEnumerator()
        {
            throw new NotImplementedException();
        }

        IEnumerator IEnumerable.GetEnumerator()
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

        public void Remove(object value)
        {
            throw new NotImplementedException();
        }

        public struct Enumerator : IEnumerator
        {
            private List<T> list;

            public object Current => throw new NotImplementedException();

            private int _getRandom()
            {
                return (new Random()).Next();
            }
            private bool _getBool()
            {
                return _getRandom() % 2 == 0;
            }
            internal Enumerator(List<T> lst)
            {
                list = lst;
            }

            private bool MoveNextRare()
            {
                list.ToString();
                if (_getBool())
                    throw new InvalidOperationException();
                
                return false;
            }
            
            void System.Collections.IEnumerator.Reset()
            {
                list.ToString();
                if (_getBool())
                    throw new InvalidOperationException();
            }

            public bool MoveNext()
            {
                throw new NotImplementedException();
            }
        }
    }
}
