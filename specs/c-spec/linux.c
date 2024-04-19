//TODO: move the file to a special folder 'linux-kernel'.
#include "specfunc.h"

typedef unsigned gfp_t;



/*static*/ void *kcalloc(size_t n, size_t size, gfp_t flags) {
	//return kmalloc_array(n, size, flags | __GFP_ZERO);
}

/*static*/ void *kmalloc_array(size_t n, size_t size, gfp_t flags) {
	//if (size != 0 && n > SIZE_MAX / size)
	//	return NULL;
	//return __kmalloc(n * size, flags);
}

/*static*/ void *kzalloc_node(size_t size, gfp_t flags, int node) {
	//return kmalloc_node(size, flags | __GFP_ZERO, node);
}

#define KRAWMALLOC(size)     void *ptr;\
    sf_overwrite(&ptr);\
    sf_overwrite(ptr);\
    sf_set_alloc_possible_null(ptr, size);\
    sf_new(ptr, KMALLOC_CATEGORY);\
    sf_raw_new(ptr);\
    sf_set_buf_size(ptr, size);\
    return ptr;

#define KMALLOC(size)     void *ptr;\
    sf_overwrite(&ptr);\
    sf_overwrite(ptr);\
    sf_set_alloc_possible_null(ptr, size);\
    sf_new(ptr, KMALLOC_CATEGORY);\
    sf_set_buf_size(ptr, size);\
    return ptr;

#define STRDUP()     void *ptr;\
    sf_overwrite(&ptr);\
    sf_overwrite(ptr);\
    sf_set_alloc_possible_null(ptr);\
    sf_new(ptr, KMALLOC_CATEGORY);\
    return ptr;

/*static*/ void *kmalloc(size_t size, gfp_t flags) {
	KMALLOC(size);
}

/*static*/ void *kzalloc(size_t size, gfp_t flags) {
}

void *__kmalloc(size_t size, gfp_t flags) {
    //KRAWMALLOC(size);
	KMALLOC(size);//note: about raw initializing: flags may be __GFP_ZERO - init by zero
}

void *__kmalloc_node(size_t size, gfp_t flags, int node) {
	//KMALLOC_CATEGORY ??
	//KRAWMALLOC(size);
	KMALLOC(size);//note: about raw initializing: flags may be __GFP_ZERO - init by zero
}

void *kmemdup(const void *src, size_t len, gfp_t gfp) {
	//KMALLOC_CATEGORY ??
	KMALLOC(len);
}

void *memdup_user(const void /*__user*/ *src, size_t len) {
	//KMALLOC_CATEGORY ??
	KMALLOC(len);
}

char *kstrdup(const char *s, gfp_t gfp) {
	STRDUP();
}

char *kasprintf(gfp_t gfp, const char *fmt, ...) {
	STRDUP();
}

void kfree(const void *x) {
    //sf_overwrite(x);
    sf_delete(x, KMALLOC_CATEGORY);
}

void kzfree(const void *x) {
	//sf_overwrite(x);
    sf_delete(x, KMALLOC_CATEGORY);
	//fill with 0
}

struct raw_spinlock;
typedef struct raw_spinlock raw_spinlock_t;

void _raw_spin_lock(raw_spinlock_t *mutex) {
    sf_lock(mutex);
}

void _raw_spin_unlock(raw_spinlock_t *mutex) {
    sf_unlock(mutex);
}

int  _raw_spin_trylock(raw_spinlock_t *mutex) {
	sf_trylock(mutex);
}

void __raw_spin_lock(raw_spinlock_t *mutex) {
    sf_lock(mutex);
}

void __raw_spin_unlock(raw_spinlock_t *mutex) {
    sf_unlock(mutex);
}

int  __raw_spin_trylock(raw_spinlock_t *mutex) {
	sf_trylock(mutex);
}

void *vmalloc(unsigned long size) {
    void *ptr;
    sf_overwrite(&ptr);
    sf_overwrite(ptr);
    sf_set_alloc_possible_null(ptr, size);
    sf_new(ptr, VMALLOC_CATEGORY);
    sf_set_buf_size(ptr, size);
    return ptr;
}

void vfree(const void *addr) {
    //sf_overwrite(addr);
    sf_delete(addr, VMALLOC_CATEGORY);
}

void *vrealloc(void *ptr, size_t size) {
	sf_escape(ptr);

    sf_set_trusted_sink_int(size);

    void *retptr;
    sf_overwrite(&retptr);
    sf_overwrite(retptr);
	sf_uncontrolled_ptr(retptr);
    sf_set_alloc_possible_null(retptr, size);
    sf_new(retptr, VMALLOC_CATEGORY);
    sf_set_buf_size(retptr, size);
    return retptr;
}

typedef char vchar_t;

vchar_t* vdup(vchar_t* src) {
    vchar_t* res;
    sf_overwrite(&res);
    sf_overwrite(res);

    sf_set_alloc_possible_null(res);
    sf_new(res, VMALLOC_CATEGORY);
    sf_strdup_res(res);
    return res;
}

#define __SVACE_DUMMYTYPE__(TYPENAME) struct TYPENAME { void *ptr; }
__SVACE_DUMMYTYPE__(tty_driver);
__SVACE_DUMMYTYPE__(platform_device);
__SVACE_DUMMYTYPE__(platform_driver);
__SVACE_DUMMYTYPE__(miscdevice);
/*__SVACE_DUMMYTYPE__(file_operations);*/
__SVACE_DUMMYTYPE__(input_dev);
__SVACE_DUMMYTYPE__(device);
__SVACE_DUMMYTYPE__(snd_soc_codec_drive);
__SVACE_DUMMYTYPE__(class);
__SVACE_DUMMYTYPE__(device_attribute);
/*__SVACE_DUMMYTYPE__(proc_dir_entry);*/
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

#define __my_acquire__(category) \
{ \
    void *ptr; \
    sf_overwrite(&ptr); \
    sf_overwrite(ptr); \
    sf_set_possible_null(ptr); \
    sf_handle_acquire(ptr, (category)); \
    return ptr; \
}

#define __my_release__(ptr, category) \
{ \
    sf_handle_release((ptr), (category)); \
}

#define __my_ptr_acquire__(s, category) \
{ \
    if (s) \
        sf_handle_acquire((s)->ptr, (category)); \
}

#define __my_ptr_release__(s, category) \
{ \
  if (s) \
    sf_handle_release((s)->ptr, (category)); \
}

#define __my_ptr_might_acquire__(s, category) \
{ \
    int ret; \
    sf_overwrite(&ret); \
    sf_overwrite((s)->ptr); \
    sf_handle_acquire((s)->ptr, (category)); \
    sf_not_acquire_if_less((s)->ptr, ret, 0); \
    return ret; \
}

#define __my_ptr_might_release__(s, category) \
{ \
  if (s) \
    sf_handle_release((s)->ptr, (category)); \
  return 0; \
}

int tty_register_driver(struct tty_driver *driver)
{
    __my_ptr_might_acquire__(driver, TTY_REGISTER_DRIVER_CATEGORY)
}

int tty_unregister_driver(struct tty_driver *driver)
{
    __my_ptr_might_release__(driver, TTY_REGISTER_DRIVER_CATEGORY)
}

int device_create_file(struct device *dev, struct device_attribute *dev_attr)
{
    __my_ptr_might_acquire__(dev_attr, DEVICE_CREATE_FILE_CATEGORY)
}

void device_remove_file(struct device *dev, struct device_attribute *dev_attr)
{
    __my_ptr_release__(dev_attr, DEVICE_CREATE_FILE_CATEGORY)
}

int platform_device_register(struct platform_device *pdev)
{
    __my_ptr_might_acquire__(pdev, PLATFORM_DEVICE_REGISTER_CATEGORY)
}

void platform_device_unregister(struct platform_device *pdev)
{
    __my_ptr_release__(pdev, PLATFORM_DEVICE_REGISTER_CATEGORY)
}

int platform_driver_register(struct platform_driver *drv)
{
    __my_ptr_might_acquire__(drv, PLATFORM_DRIVER_REGISTER_CATEGORY)
}

void platform_driver_unregister(struct platform_driver *drv)
{
    __my_ptr_release__(drv, PLATFORM_DRIVER_REGISTER_CATEGORY)
}

int misc_register(struct miscdevice *misc)
{
    __my_ptr_might_acquire__(misc, MISC_REGISTER_CATEGORY)
}

int misc_deregister(struct miscdevice *misc)
{
    __my_ptr_might_release__(misc, MISC_REGISTER_CATEGORY)
}

int input_register_device(struct input_dev *dev)
{
    __my_ptr_might_acquire__(dev, INPUT_REGISTER_DEVICE_CATEGORY)
}

void input_unregister_device(struct input_dev *dev)
{
    __my_ptr_release__(dev, INPUT_REGISTER_DEVICE_CATEGORY)
}

struct input_dev *input_allocate_device(void)
{
    __my_acquire__(INPUT_ALLOCATE_DEVICE_CATEGORY)
}

void input_free_device(struct input_dev *dev)
{
    __my_release__(dev, INPUT_ALLOCATE_DEVICE_CATEGORY)
}

int rfkill_register(struct rfkill *rfkill)
{
    __my_ptr_might_acquire__(rfkill, RFKILL_REGISTER_CATEGORY)
}

void rfkill_unregister(struct rfkill *rfkill)
{
    __my_ptr_release__(rfkill, RFKILL_REGISTER_CATEGORY)
}

int snd_soc_register_codec(struct device *dev,
      const struct snd_soc_codec_driver *codec_drv,
      struct snd_soc_dai_driver *dai_drv,
      int num_dai)
{
    __my_ptr_might_acquire__(dev, SND_SOC_REGISTER_CODEC_CATEGORY)
}

void snd_soc_unregister_codec(struct device *dev)
{
    __my_ptr_release__(dev, SND_SOC_REGISTER_CODEC_CATEGORY)

}

struct class *class_create(void *owner, void *name)
{
    __my_acquire__(CLASS_CREATE_CATEGORY)
}

struct class *__class_create(void *owner, void *name)
{
    __my_acquire__(CLASS_CREATE_CATEGORY)
}

void class_destroy(struct class *cls)
{
    __my_release__(cls, CLASS_CREATE_CATEGORY)
}

struct platform_device *platform_device_alloc(const char *name, int id)
{
    __my_acquire__(PLATFORM_DEVICE_ALLOC_CATEGORY)
}

void platform_device_put(struct platform_device *pdev)
{
    __my_release__(pdev, PLATFORM_DEVICE_ALLOC_CATEGORY)
}

typedef int bool;

void rfkill_alloc(struct rfkill *rfkill, bool blocked)
{
    __my_ptr_acquire__(rfkill, RFKILL_ALLOC_CATEGORY);
}

void rfkill_destroy(struct rfkill *rfkill)
{
    //__my_ptr_release__(rfkill, RFKILL_ALLOC_CATEGORY)
}

static inline void *ioremap(struct phys_addr_t offset, unsigned long size)
{
    __my_acquire__(IOREMAP_CATEGORY)
}

static inline void iounmap(void *addr)
{
    __my_release__(addr, IOREMAP_CATEGORY)
}

int clk_enable(struct clk *clk)
{
    __my_ptr_might_acquire__(clk, CLK_ENABLE_CATEGORY)
}

void clk_disable(struct clk *clk)
{
    __my_ptr_release__(clk, CLK_ENABLE_CATEGORY)
}

struct regulator *regulator_get(struct device *dev, const char *id)
{
    __my_acquire__(REGULATOR_GET_CATEGORY)
}

void regulator_put(struct regulator *regulator)
{
    __my_release__(regulator, REGULATOR_GET_CATEGORY)
}

int regulator_enable(struct regulator *regulator)
{
    __my_ptr_might_acquire__(regulator, REGULATOR_ENABLE_CATEGORY)
}

int regulator_disable(struct regulator *regulator)
{
    __my_ptr_might_release__(regulator, REGULATOR_ENABLE_CATEGORY)
}

struct workqueue_struct *create_workqueue(void *name)
{
    __my_acquire__(CREATE_WORKQUEUE_CATEGORY)
}

struct workqueue_struct *create_singlethread_workqueue(void *name)
{
    __my_acquire__(CREATE_WORKQUEUE_CATEGORY)
}

struct workqueue_struct *create_freezable_workqueue(void *name)
{
    __my_acquire__(CREATE_WORKQUEUE_CATEGORY)
}

void destroy_workqueue(struct workqueue_struct *wq)
{
    __my_release__(wq, CREATE_WORKQUEUE_CATEGORY)
}

void add_timer (struct timer_list *timer)
{
    __my_ptr_acquire__(timer, ADD_TIMER_CATEGORY)
}

int del_timer(struct timer_list *timer)
{
    __my_ptr_might_release__(timer, ADD_TIMER_CATEGORY)
}

struct task_struct *kthread_create(int(*threadfn)(void *data), void *data, const char namefmt[])
{
    __my_acquire__(KTHREAD_CREATE_CATEGORY)
}

void put_task_struct(struct task_struct *t)
{
    __my_release__(t, KTHREAD_CREATE_CATEGORY)
}

struct tty_driver *alloc_tty_driver(int lines)
{
    __my_acquire__(ALLOC_TTY_DRIVER_CATEGORY)
}

struct tty_driver *__alloc_tty_driver(int lines)
{
    __my_acquire__(ALLOC_TTY_DRIVER_CATEGORY)
}

void put_tty_driver(struct tty_driver *d)
{
    __my_release__(d, ALLOC_TTY_DRIVER_CATEGORY)
}

