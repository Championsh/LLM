 
#include "specfunc.h"

typedef unsigned gfp_t;



  void *kcalloc(size_t n, size_t size, gfp_t flags);

  void *kmalloc_array(size_t n, size_t size, gfp_t flags);

  void *kzalloc_node(size_t size, gfp_t flags, int node);

#define KRAWMALLOC(size)    void *ptr;\
    sf_overwrite(&ptr);\
    sf_overwrite(ptr);\
    sf_set_alloc_possible_null(ptr, size);\
    sf_new(ptr, KMALLOC_CATEGORY);\
    sf_raw_new(ptr);\
    sf_set_buf_size(ptr, size);\
    return ptr;

#define KMALLOC(size)    void *ptr;\
    sf_overwrite(&ptr);\
    sf_overwrite(ptr);\
    sf_set_alloc_possible_null(ptr, size);\
    sf_new(ptr, KMALLOC_CATEGORY);\
    sf_set_buf_size(ptr, size);\
    return ptr;

#define STRDUP()    void *ptr;\
    sf_overwrite(&ptr);\
    sf_overwrite(ptr);\
    sf_set_alloc_possible_null(ptr);\
    sf_new(ptr, KMALLOC_CATEGORY);\
    return ptr;

  void *kmalloc(size_t size, gfp_t flags);

  void *kzalloc(size_t size, gfp_t flags);

void *__kmalloc(size_t size, gfp_t flags);

void *__kmalloc_node(size_t size, gfp_t flags, int node);

void *kmemdup(const void *src, size_t len, gfp_t gfp);

void *memdup_user(const void   *src, size_t len);

char *kstrdup(const char *s, gfp_t gfp);

char *kasprintf(gfp_t gfp, const char *fmt, ...);

void kfree(const void *x);

void kzfree(const void *x);

struct raw_spinlock;
typedef struct raw_spinlock raw_spinlock_t;

void _raw_spin_lock(raw_spinlock_t *mutex);

void _raw_spin_unlock(raw_spinlock_t *mutex);

int  _raw_spin_trylock(raw_spinlock_t *mutex);

void __raw_spin_lock(raw_spinlock_t *mutex);

void __raw_spin_unlock(raw_spinlock_t *mutex);

int  __raw_spin_trylock(raw_spinlock_t *mutex);

void *vmalloc(unsigned long size);

void vfree(const void *addr);

void *vrealloc(void *ptr, size_t size);

typedef char vchar_t;

vchar_t* vdup(vchar_t* src);

#define __SVACE_DUMMYTYPE__(TYPENAME)struct TYPENAME ;
__SVACE_DUMMYTYPE__(tty_driver);
__SVACE_DUMMYTYPE__(platform_device);
__SVACE_DUMMYTYPE__(platform_driver);
__SVACE_DUMMYTYPE__(miscdevice);
 
__SVACE_DUMMYTYPE__(input_dev);
__SVACE_DUMMYTYPE__(device);
__SVACE_DUMMYTYPE__(snd_soc_codec_drive);
__SVACE_DUMMYTYPE__(class);
__SVACE_DUMMYTYPE__(device_attribute);
 
__SVACE_DUMMYTYPE__(task_struct);
__SVACE_DUMMYTYPE__(rfkill);
__SVACE_DUMMYTYPE__(phys_addr_t);
__SVACE_DUMMYTYPE__(clk);
__SVACE_DUMMYTYPE__(regulator);
__SVACE_DUMMYTYPE__(workqueue_struct);
__SVACE_DUMMYTYPE__(timer_list);

#define TTY_REGISTER_DRIVER_CATEGORY		10000
#define DEVICE_CREATE_FILE_CATEGORY		10001
#define PLATFORM_DEVICE_REGISTER_CATEGORY	10002
#define PLATFORM_DRIVER_REGISTER_CATEGORY	10003
#define MISC_REGISTER_CATEGORY			10004
#define INPUT_REGISTER_DEVICE_CATEGORY		10005
#define INPUT_ALLOCATE_DEVICE_CATEGORY		10006
#define RFKILL_REGISTER_CATEGORY		10007
#define SND_SOC_REGISTER_CODEC_CATEGORY		10008
#define CLASS_CREATE_CATEGORY			10009
#define PLATFORM_DEVICE_ALLOC_CATEGORY		10010
#define RFKILL_ALLOC_CATEGORY			10011
#define IOREMAP_CATEGORY			10012
#define CLK_ENABLE_CATEGORY			10013
#define REGULATOR_GET_CATEGORY			10014
#define REGULATOR_ENABLE_CATEGORY		10015
#define CREATE_WORKQUEUE_CATEGORY		10016
#define ADD_TIMER_CATEGORY			10017
#define KTHREAD_CREATE_CATEGORY			10018
#define ALLOC_TTY_DRIVER_CATEGORY		10019

#define __my_acquire__(category)\
;

#define __my_release__(ptr, category)\
;

#define __my_ptr_acquire__(s, category)\
;

#define __my_ptr_release__(s, category)\
;

#define __my_ptr_might_acquire__(s, category)\
;

#define __my_ptr_might_release__(s, category)\
;

int tty_register_driver(struct tty_driver *driver)
;

int tty_unregister_driver(struct tty_driver *driver)
;

int device_create_file(struct device *dev, struct device_attribute *dev_attr)
;

void device_remove_file(struct device *dev, struct device_attribute *dev_attr)
;

int platform_device_register(struct platform_device *pdev)
;

void platform_device_unregister(struct platform_device *pdev)
;

int platform_driver_register(struct platform_driver *drv)
;

void platform_driver_unregister(struct platform_driver *drv)
;

int misc_register(struct miscdevice *misc)
;

int misc_deregister(struct miscdevice *misc)
;

int input_register_device(struct input_dev *dev)
;

void input_unregister_device(struct input_dev *dev)
;

struct input_dev *input_allocate_device(void)
;

void input_free_device(struct input_dev *dev)
;

int rfkill_register(struct rfkill *rfkill)
;

void rfkill_unregister(struct rfkill *rfkill)
;

int snd_soc_register_codec(struct device *dev,
      const struct snd_soc_codec_driver *codec_drv,
      struct snd_soc_dai_driver *dai_drv,
      int num_dai)
;

void snd_soc_unregister_codec(struct device *dev)
;

struct class *class_create(void *owner, void *name)
;

struct class *__class_create(void *owner, void *name)
;

void class_destroy(struct class *cls)
;

struct platform_device *platform_device_alloc(const char *name, int id)
;

void platform_device_put(struct platform_device *pdev)
;

typedef int bool;

void rfkill_alloc(struct rfkill *rfkill, bool blocked)
;

void rfkill_destroy(struct rfkill *rfkill)
;

static inline void *ioremap(struct phys_addr_t offset, unsigned long size)
;

static inline void iounmap(void *addr)
;

int clk_enable(struct clk *clk)
;

void clk_disable(struct clk *clk)
;

struct regulator *regulator_get(struct device *dev, const char *id)
;

void regulator_put(struct regulator *regulator)
;

int regulator_enable(struct regulator *regulator)
;

int regulator_disable(struct regulator *regulator)
;

struct workqueue_struct *create_workqueue(void *name)
;

struct workqueue_struct *create_singlethread_workqueue(void *name)
;

struct workqueue_struct *create_freezable_workqueue(void *name)
;

void destroy_workqueue(struct workqueue_struct *wq)
;

void add_timer (struct timer_list *timer)
;

int del_timer(struct timer_list *timer)
;

struct task_struct *kthread_create(int(*threadfn)(void *data), void *data, const char namefmt[])
;

void put_task_struct(struct task_struct *t)
;

struct tty_driver *alloc_tty_driver(int lines)
;

struct tty_driver *__alloc_tty_driver(int lines)
;

void put_tty_driver(struct tty_driver *d)
;

