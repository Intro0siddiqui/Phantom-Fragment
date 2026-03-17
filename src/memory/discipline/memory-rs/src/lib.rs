use std::ffi::c_void;
use std::ops::{Deref, DerefMut};
use std::os::raw::c_int;
use std::ptr::NonNull;

extern "C" {
    fn phantom_buffer_pool_create(buffer_size: usize, initial_capacity: usize) -> *mut c_void;
    fn phantom_buffer_pool_destroy(pool: *mut c_void);
    fn phantom_buffer_pool_get(pool: *mut c_void, out_len: *mut usize) -> *mut u8;
    fn phantom_buffer_pool_put(pool: *mut c_void, ptr: *mut u8, len: usize);
    fn phantom_ksm_enable() -> c_int;
}

pub struct BufferPool {
    inner: NonNull<c_void>,
}

pub struct BufferGuard<'a> {
    ptr: NonNull<u8>,
    len: usize,
    pool: &'a BufferPool,
}

impl Deref for BufferGuard<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl DerefMut for BufferGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for BufferGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            phantom_buffer_pool_put(self.pool.inner.as_ptr(), self.ptr.as_ptr(), self.len);
        }
    }
}

impl BufferPool {
    pub fn new(buffer_size: usize, initial_capacity: usize) -> Option<Self> {
        let inner = unsafe { phantom_buffer_pool_create(buffer_size, initial_capacity) };
        NonNull::new(inner).map(|inner| Self { inner })
    }

    pub fn get(&self) -> Option<BufferGuard<'_>> {
        let mut len: usize = 0;
        let ptr = unsafe { phantom_buffer_pool_get(self.inner.as_ptr(), &mut len) };
        NonNull::new(ptr).map(|ptr| BufferGuard {
            ptr,
            len,
            pool: self,
        })
    }
}

impl Drop for BufferPool {
    fn drop(&mut self) {
        unsafe { phantom_buffer_pool_destroy(self.inner.as_ptr()) };
    }
}

pub fn enable_ksm() -> Result<(), String> {
    let rc = unsafe { phantom_ksm_enable() };
    if rc == 0 {
        Ok(())
    } else {
        Err("Failed to enable KSM".to_string())
    }
}

#[cfg(feature = "numa")]
extern "C" {
    fn phantom_numa_available() -> c_int;
    fn phantom_numa_max_node() -> c_int;
    fn phantom_numa_bind_node(node: c_int) -> c_int;
    fn phantom_numa_alloc_on_node(size: usize, node: c_int) -> *mut c_void;
    fn phantom_numa_free(start: *mut c_void, size: usize);
}

#[cfg(feature = "numa")]
pub struct NumaManager;

#[cfg(feature = "numa")]
impl NumaManager {
    pub fn is_available() -> bool {
        unsafe { phantom_numa_available() != -1 }
    }

    pub fn max_node() -> i32 {
        unsafe { phantom_numa_max_node() }
    }

    pub fn bind_node(node: i32) {
        let _ = unsafe { phantom_numa_bind_node(node) };
    }

    pub fn alloc_on_node(size: usize, node: i32) -> Option<*mut c_void> {
        let ptr = unsafe { phantom_numa_alloc_on_node(size, node) };
        if ptr.is_null() {
            None
        } else {
            Some(ptr)
        }
    }

    /// # Safety
    ///
    /// This function is unsafe because it dereferences a raw pointer.
    /// The caller must ensure that:
    /// - `ptr` is a valid pointer returned by `alloc_on_node`
    /// - `size` matches the size used during allocation
    /// - The memory has not already been freed
    pub unsafe fn free(ptr: *mut c_void, size: usize) {
        phantom_numa_free(ptr, size)
    }
}

extern "C" {
    fn phantom_set_cpu_affinity(cpu_ids: *const u32, len: usize) -> c_int;
}

pub fn set_cpu_affinity(cpus: &[u32]) -> Result<(), String> {
    let ret = unsafe { phantom_set_cpu_affinity(cpus.as_ptr(), cpus.len()) };
    if ret == 0 {
        Ok(())
    } else {
        Err("Failed to set CPU affinity".to_string())
    }
}
