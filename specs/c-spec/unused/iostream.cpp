// This function is now defined in ostream.cpp
//
// #ifdef USE_CLANG
//     namespace std {
// 	template <class charT/*, class traits = char_traits<charT>*/> class basic_ostream;
//         typedef basic_ostream<char> ostream;
//     }
// #else
//     #include <iostream>
// #endif

// //std::basic_ostream<char, std::char_traits<char> >::operator<<(int)
// extern "C" std::ostream& _ZNSolsEi(std::ostream& s, int a) {
// 	return s;
// }
