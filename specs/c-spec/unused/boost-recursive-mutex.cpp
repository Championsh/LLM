#include "specfunc.h"

namespace boost {
    class recursive_mutex
    {
    public:
        void do_lock();

        void do_unlock();

        void lock();

        void unlock();
    };

    void recursive_mutex::do_lock() {
        //nothing for preventing DOUBLE_LOCK
        //it is recursive mutex
    }

    void recursive_mutex::do_unlock() {
    }

    void recursive_mutex::lock() {
    }

    void recursive_mutex::unlock() {
    }
}
