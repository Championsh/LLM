using System;
using System.Collections.Generic;
using System.Runtime.Serialization;

namespace System.Collections.Generic
{
    public class Dictionary<TKey, TValue> : CSharpCodeChecker_Kostil.HasItemObject<TValue>, IDictionary<TKey, TValue>, IDictionary
    {
        private struct Entry
        {
            public int hashCode;    
            public int next;        
            public TKey key;        
            public TValue value;    
        }

        private int count;
        private int version;
        private int freeList;
        private int freeCount;

        public ICollection<TKey> Keys => throw new NotImplementedException();

        public ICollection<TValue> Values => throw new NotImplementedException();

        public int Count => throw new NotImplementedException();

        public bool IsReadOnly => throw new NotImplementedException();

        public bool IsFixedSize => throw new NotImplementedException();

        ICollection IDictionary.Keys => throw new NotImplementedException();

        ICollection IDictionary.Values => throw new NotImplementedException();

        public bool IsSynchronized => throw new NotImplementedException();

        public object SyncRoot => throw new NotImplementedException();

        public TValue this[TKey key] { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

        private bool _getBool()
        {
            return _getRandom() % 2 == 0;
        }
        private bool _getBoolKey(TKey key)
        {
            return _getRandom() % 2 == 0;
        }
        private TKey _getDefaultKey()
        {
            return default(TKey);
        }
        
        public Dictionary(int capacity, IEqualityComparer<TKey> comparer)
        {
            if (capacity < 0)
                throw new ArgumentOutOfRangeException();

            if (capacity > 0)
                freeList = -1;
        }

        public bool ContainsKey(TKey key)
        {
            if (key == null)
                throw new ArgumentNullException();

            return _getBool();
        }

        public bool ContainsValue(TValue value)
        {
            return _getBool();
        }

        public void Add(TKey key, TValue value)
        {
            if (key == null)
                throw new ArgumentNullException();
            if (_getBoolKey(key))
                throw new ArgumentException();

            Item = value;

            if (freeCount > 0)
            {
                freeList = _getRandom();
                freeCount--;
            }
            else
                count++;
        }

        public void Clear()
        {
            if (count > 0)
            {
                freeCount = 0;
                freeList = -1;
                count = 0;
            }
        }

        public virtual void OnDeserialization(Object sender)
        {
            if (_getBool())
                throw new InvalidOperationException();

            if (_getBool())
            {
                freeList = -1;
                if (_getBool())
                    throw new SerializationException();
                if (_getBool())
                    throw new ArgumentException();
            }
        }

        public bool Remove(TKey key)
        {
            if (key == null)
                throw new ArgumentNullException();

            if (_getBool())
                for (int i = _getRandom(); i >= 0; i -= _getRandom())
                    if (_getBoolKey(key))
                    {
                        freeList = i;
                        freeCount++;
                        return true;
                    }

            return false;
        }

        public bool TryGetValue(TKey key, out TValue value)
        {
            if (key == null)
                throw new ArgumentNullException();
            
            if (_getBool())
            {
                value = Item;
                return true;
            }

            value = default(TValue);
            return false;
        }

        public void CopyTo(Array array, int index)
        {
            if (array == null)
                throw new ArgumentNullException();
            if (array.Rank != 1)
                throw new ArgumentException();
            if (array.GetLowerBound(0) != 0)
                throw new ArgumentException();
            if (index < 0 || index > array.Length)
                throw new ArgumentOutOfRangeException();
            if (array.Length - index < count)
                throw new ArgumentException();

            if (_getBool() && !(array is DictionaryEntry[]))
            {
                object[] objects = array as object[];
                if (objects == null)
                    throw new ArgumentException();

                try
                {
                    for (int i = 0; i < count; i++)
                    {
                        if (_getBool())
                        {
                            objects[index++] = new KeyValuePair<TKey, TValue>(_getDefaultKey(), Item);
                        }
                    }
                }
                catch (ArrayTypeMismatchException)
                {
                    throw new ArgumentException();
                }
            }
        }

        object IDictionary.this[object key]
        {
            get
            {
                if (key == null)
                    throw new ArgumentNullException();

                if (key is TKey && _getBool())
                    return Item;
                return null;
            }
            set
            {
                if (key == null)
                    throw new ArgumentNullException();
                if (value == null && !(default(TValue) == null))
                    throw new ArgumentNullException();

                try
                {
                    TKey tempKey = (TKey)key;
                    Item = (TValue)value;
                }
                catch (InvalidCastException)
                {
                    throw new ArgumentException();
                }
            }
        }

        /*
        TValue this[TKey key]
        {
            get
            {
                if (key == null)
                    throw new ArgumentNullException();

                if (_getBool())
                    return Item;
                throw new KeyNotFoundException();
            }
            set
            {
                if (key == null)
                    throw new ArgumentNullException();
                if (value == null && default(TValue) != null)
                    throw new ArgumentNullException();

                Item = value;
            }
        }
        */
        
        void IDictionary.Add(object key, object value)
        {
            if (key == null)
                throw new ArgumentNullException();
            if (value == null && !(default(TValue) == null))
                throw new ArgumentNullException();

            try
            {
                TKey tempKey = (TKey)key;
                TValue tempValue = (TValue)value;

                try
                {
                    if (freeCount > 0)
                    {
                        freeList = _getRandom();
                        freeCount--;
                    }
                    else
                        count++;

                    if (_getBool())
                        throw new InvalidCastException();
                }
                catch (InvalidCastException)
                {
                    throw new ArgumentException();
                }
            }
            catch (InvalidCastException)
            {
                throw new ArgumentException();
            }
        }

        public void Add(KeyValuePair<TKey, TValue> item)
        {
            throw new NotImplementedException();
        }

        public bool Contains(KeyValuePair<TKey, TValue> item)
        {
            throw new NotImplementedException();
        }

        public void CopyTo(KeyValuePair<TKey, TValue>[] array, int arrayIndex)
        {
            throw new NotImplementedException();
        }

        public bool Remove(KeyValuePair<TKey, TValue> item)
        {
            throw new NotImplementedException();
        }

        public IEnumerator<KeyValuePair<TKey, TValue>> GetEnumerator()
        {
            throw new NotImplementedException();
        }

        IEnumerator IEnumerable.GetEnumerator()
        {
            throw new NotImplementedException();
        }

        public bool Contains(object key)
        {
            throw new NotImplementedException();
        }

        IDictionaryEnumerator IDictionary.GetEnumerator()
        {
            throw new NotImplementedException();
        }

        public void Remove(object key)
        {
            throw new NotImplementedException();
        }

        public struct Enumerator<TKey, TValue> : IDictionaryEnumerator
        {
            private Dictionary<TKey, TValue> dictionary;
            private int version;
            private int index;
            private KeyValuePair<TKey, TValue> current;
            private int getEnumeratorRetType;  // What should Enumerator.Current return?

            internal const int DictEntry = 1;
            internal const int KeyValuePair = 2;
            
            private bool _getBool()
            {
                return (new Random()).Next() % 2 == 0;
            }

            internal Enumerator(Dictionary<TKey, TValue> dictionary, int getEnumeratorRetType)
            {
                this.dictionary = dictionary;
                version = dictionary.version;
                index = 0;
                this.getEnumeratorRetType = getEnumeratorRetType;
                current = new KeyValuePair<TKey, TValue>();
            }

            public bool MoveNext()
            {
                if (version != dictionary.version)
                    throw new InvalidOperationException();

                while ((uint)index < (uint)dictionary.count)
                {
                    index++;

                    if (_getBool())
                    {
                        current = new KeyValuePair<TKey, TValue>(dictionary._getDefaultKey(), dictionary.Item);

                        return true;
                    }
                }

                index = dictionary.count + 1;
                current = new KeyValuePair<TKey, TValue>();

                return false;
            }

            public KeyValuePair<TKey, TValue> Current
            {
                get { return current; }
            }

            object IEnumerator.Current
            {
                get
                {
                    if (index == 0 || (index == dictionary.count + 1))
                        throw new InvalidOperationException();

                    if (getEnumeratorRetType == DictEntry)
                        return new System.Collections.DictionaryEntry(current.Key, current.Value);
                    else
                        return new KeyValuePair<TKey, TValue>(current.Key, current.Value);
                }
            }

            void IEnumerator.Reset()
            {
                if (version != dictionary.version)
                    throw new InvalidOperationException();

                index = 0;
                current = new KeyValuePair<TKey, TValue>();
            }

            DictionaryEntry IDictionaryEnumerator.Entry
            {
                get
                {
                    if (index == 0 || (index == dictionary.count + 1))
                        throw new InvalidOperationException();

                    return new DictionaryEntry(current.Key, current.Value);
                }
            }

            object IDictionaryEnumerator.Key
            {
                get
                {
                    if (index == 0 || (index == dictionary.count + 1))
                        throw new InvalidOperationException();

                    return current.Key;
                }
            }

            object IDictionaryEnumerator.Value
            {
                get
                {
                    if (index == 0 || (index == dictionary.count + 1))
                        throw new InvalidOperationException();

                    return current.Value;
                }
            }
        }
    }
}