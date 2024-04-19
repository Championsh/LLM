template< class T >
struct allocator {
	allocator() {}

	allocator( const allocator& other) {}

	template< class U > 
	allocator( const allocator<U>& other) {}

	~allocator() {}
};
