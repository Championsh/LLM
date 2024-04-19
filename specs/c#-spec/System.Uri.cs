using System;
using System.Runtime.Serialization;

namespace System
{
    public class Uri : ISerializable
    {
        // TODO: add models for Escape, Unescape, constructor etc.
        public void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            throw new NotImplementedException();
        }
    }
}