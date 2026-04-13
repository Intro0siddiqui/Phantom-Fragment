#![cfg_attr(not(feature = "std"), no_std)]

//! Types used across the Phantom Fragment system
//!
//! This crate contains shared data structures and type definitions
//! that are used by multiple components in the system.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::ffi::CString;
#[cfg(not(feature = "std"))]
use alloc::string::String;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::ffi::CString;
#[cfg(feature = "std")]
use std::string::String;
#[cfg(feature = "std")]
use std::vec::Vec;

use core::ffi::{c_char, CStr};
use core::ptr;
use serde::{Deserialize, Serialize};

#[repr(C)]
pub struct CContainer {
    id: *const c_char,
    workdir: *const c_char,
    binds: *const *const c_char,
    binds_len: usize,
    env_keys: *const *const c_char,
    env_values: *const *const c_char,
    env_len: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum PhantomError {
    #[error("IO error: {0:?}")]
    Io(Box<dyn core::fmt::Debug + Send + Sync>),
    #[error("Serialization error: {0:?}")]
    Serialization(Box<dyn core::fmt::Debug + Send + Sync>),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Out of memory")]
    OutOfMemory,
    #[error("Fragment not found: {0}")]
    FragmentNotFound(String),
    #[error("Internal error: {0}")]
    Internal(String),
    /// Permission denied - elevated privileges required (e.g., for BPF-LSM)
    #[error("Permission denied - sudo required")]
    NeedSudo,
}

#[repr(C)]
pub struct CPhantomError {
    code: i32,
    message: *const c_char,
}

#[repr(C)]
pub struct FragmentMetadata {
    pub id: *const c_char,
    pub name: *const c_char,
    pub version: *const c_char,
    pub description: *const c_char,
}

// FFI-safe error codes
pub const PHANTOM_ERROR_SUCCESS: i32 = 0;
pub const PHANTOM_ERROR_INVALID_INPUT: i32 = -1;
pub const PHANTOM_ERROR_OUT_OF_MEMORY: i32 = -2;
pub const PHANTOM_ERROR_IO: i32 = -3;
pub const PHANTOM_ERROR_SERIALIZATION: i32 = -4;
pub const PHANTOM_ERROR_FRAGMENT_NOT_FOUND: i32 = -5;

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn phantom_container_new(
    id: *const c_char,
    workdir: *const c_char,
    binds: *const *const c_char,
    binds_len: usize,
    env_keys: *const *const c_char,
    env_values: *const *const c_char,
    env_len: usize,
    error_out: *mut *mut CPhantomError,
) -> *mut CContainer {
    if id.is_null() || workdir.is_null() {
        if !error_out.is_null() {
            let msg = c"Invalid id or workdir".as_ptr();
            unsafe {
                *error_out = create_phantom_error(PHANTOM_ERROR_INVALID_INPUT, msg);
            }
        }
        return ptr::null_mut();
    }

    let _id_str = unsafe { CStr::from_ptr(id) };
    let _workdir_str = unsafe { CStr::from_ptr(workdir) };

    // Validate binds pointer if length is non-zero
    if binds_len > 0 && binds.is_null() {
        if !error_out.is_null() {
            let msg = c"Invalid binds pointer".as_ptr();
            unsafe {
                *error_out = create_phantom_error(PHANTOM_ERROR_INVALID_INPUT, msg);
            }
        }
        return ptr::null_mut();
    }

    // Validate env pointers if length is non-zero
    if env_len > 0 && (env_keys.is_null() || env_values.is_null()) {
        if !error_out.is_null() {
            let msg = c"Invalid env pointers".as_ptr();
            unsafe {
                *error_out = create_phantom_error(PHANTOM_ERROR_INVALID_INPUT, msg);
            }
        }
        return ptr::null_mut();
    }

    let id_cstr = unsafe { CString::from_raw(id as *mut c_char) };
    let workdir_cstr = unsafe { CString::from_raw(workdir as *mut c_char) };

    let mut container = Box::new(CContainer {
        id: id_cstr.into_raw(),
        workdir: workdir_cstr.into_raw(),
        binds: ptr::null(),
        binds_len: 0,
        env_keys: ptr::null(),
        env_values: ptr::null(),
        env_len: 0,
    });

    // Copy binds
    if binds_len > 0 && !binds.is_null() {
        let mut binds_vec: Vec<*const c_char> = Vec::with_capacity(binds_len);
        for i in 0..binds_len {
            let bind_ptr = unsafe { *binds.add(i) };
            if !bind_ptr.is_null() {
                let bind_cstr = unsafe { CStr::from_ptr(bind_ptr) };
                let owned = CString::new(bind_cstr.to_bytes()).unwrap_or_default();
                binds_vec.push(owned.into_raw());
            }
        }
        container.binds = binds_vec.as_ptr();
        container.binds_len = binds_len;
        // Prevent drop of Vec to leak the pointers
        core::mem::forget(binds_vec);
    }

    // Copy env (keys and values)
    if env_len > 0 && !env_keys.is_null() && !env_values.is_null() {
        let mut keys_vec: Vec<*const c_char> = Vec::with_capacity(env_len);
        let mut values_vec: Vec<*const c_char> = Vec::with_capacity(env_len);
        for i in 0..env_len {
            let key_ptr = unsafe { *env_keys.add(i) };
            let value_ptr = unsafe { *env_values.add(i) };
            if !key_ptr.is_null() && !value_ptr.is_null() {
                let key_cstr = unsafe { CStr::from_ptr(key_ptr) };
                let value_cstr = unsafe { CStr::from_ptr(value_ptr) };
                let owned_key = CString::new(key_cstr.to_bytes()).unwrap_or_default();
                let owned_value = CString::new(value_cstr.to_bytes()).unwrap_or_default();
                keys_vec.push(owned_key.into_raw());
                values_vec.push(owned_value.into_raw());
            }
        }
        container.env_keys = keys_vec.as_ptr();
        container.env_values = values_vec.as_ptr();
        container.env_len = env_len;
        core::mem::forget(keys_vec);
        core::mem::forget(values_vec);
    }

    Box::into_raw(container)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn phantom_container_free(container: *mut CContainer) {
    if container.is_null() {
        return;
    }
    let cont = unsafe { Box::from_raw(container) };

    // Free id and workdir
    unsafe {
        if !cont.id.is_null() {
            drop(CString::from_raw(cont.id as *mut c_char));
        }
        if !cont.workdir.is_null() {
            drop(CString::from_raw(cont.workdir as *mut c_char));
        }

        // Free binds
        if cont.binds_len > 0 && !cont.binds.is_null() {
            for i in 0..cont.binds_len {
                let ptr = *cont.binds.add(i);
                if !ptr.is_null() {
                    drop(CString::from_raw(ptr as *mut c_char));
                }
            }
            // The vec was forgotten, so no need to drop
        }

        // Free env keys and values
        if cont.env_len > 0 && !cont.env_keys.is_null() && !cont.env_values.is_null() {
            for i in 0..cont.env_len {
                let key_ptr = *cont.env_keys.add(i);
                let value_ptr = *cont.env_values.add(i);
                if !key_ptr.is_null() {
                    drop(CString::from_raw(key_ptr as *mut c_char));
                }
                if !value_ptr.is_null() {
                    drop(CString::from_raw(value_ptr as *mut c_char));
                }
            }
        }
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn phantom_container_get_id(container: *const CContainer) -> *const c_char {
    if container.is_null() {
        return ptr::null();
    }
    unsafe { (*container).id }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn phantom_container_get_workdir(
    container: *const CContainer,
) -> *const c_char {
    if container.is_null() {
        return ptr::null();
    }
    unsafe { (*container).workdir }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn phantom_container_get_binds(
    container: *const CContainer,
    len_out: *mut usize,
) -> *const *const c_char {
    if container.is_null() {
        if !len_out.is_null() {
            unsafe {
                *len_out = 0;
            }
        }
        return ptr::null();
    }
    unsafe {
        if !len_out.is_null() {
            *len_out = (*container).binds_len;
        }
        (*container).binds
    }
}

#[repr(C)]
pub struct CEnvPair {
    pub keys: *const *const c_char,
    pub values: *const *const c_char,
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn phantom_container_get_env(
    container: *const CContainer,
    keys_len_out: *mut usize,
    values_len_out: *mut usize,
) -> CEnvPair {
    if container.is_null() {
        if !keys_len_out.is_null() {
            unsafe {
                *keys_len_out = 0;
            }
        }
        if !values_len_out.is_null() {
            unsafe {
                *values_len_out = 0;
            }
        }
        return CEnvPair {
            keys: ptr::null(),
            values: ptr::null(),
        };
    }
    unsafe {
        if !keys_len_out.is_null() {
            *keys_len_out = (*container).env_len;
        }
        if !values_len_out.is_null() {
            *values_len_out = (*container).env_len;
        }
        CEnvPair {
            keys: (*container).env_keys,
            values: (*container).env_values,
        }
    }
}

// Error handling functions
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn create_phantom_error(
    code: i32,
    message: *const c_char,
) -> *mut CPhantomError {
    if message.is_null() {
        return ptr::null_mut();
    }
    let msg = unsafe { CStr::from_ptr(message) };
    let msg_cstr = CString::new(msg.to_bytes()).unwrap_or_default();
    let err = Box::new(CPhantomError {
        code,
        message: msg_cstr.into_raw(),
    });
    Box::into_raw(err)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn phantom_error_get_code(err: *const CPhantomError) -> i32 {
    if err.is_null() {
        PHANTOM_ERROR_INVALID_INPUT
    } else {
        unsafe { (*err).code }
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn phantom_error_get_message(err: *const CPhantomError) -> *const c_char {
    if err.is_null() {
        ptr::null()
    } else {
        unsafe { (*err).message }
    }
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn phantom_error_free(err: *mut CPhantomError) {
    if err.is_null() {
        return;
    }
    unsafe {
        if !(*err).message.is_null() {
            drop(CString::from_raw((*err).message as *mut c_char));
        }
        drop(Box::from_raw(err));
    }
}

// FragmentMetadata FFI (simplified, assuming string fields)
#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn phantom_fragment_metadata_new(
    id: *const c_char,
    name: *const c_char,
    version: *const c_char,
    description: *const c_char,
    error_out: *mut *mut CPhantomError,
) -> *mut FragmentMetadata {
    if id.is_null() || name.is_null() || version.is_null() {
        if !error_out.is_null() {
            let msg = c"Missing required fields".as_ptr();
            unsafe {
                *error_out = create_phantom_error(PHANTOM_ERROR_INVALID_INPUT, msg);
            }
        }
        return ptr::null_mut();
    }

    let _id_cstr = unsafe { CStr::from_ptr(id) };
    let _name_cstr = unsafe { CStr::from_ptr(name) };
    let _version_cstr = unsafe { CStr::from_ptr(version) };
    let desc_cstr = if !description.is_null() {
        unsafe { Some(CStr::from_ptr(description)) }
    } else {
        None
    };

    let id_owned = unsafe { CString::from_raw(id as *mut c_char) };
    let name_owned = unsafe { CString::from_raw(name as *mut c_char) };
    let version_owned = unsafe { CString::from_raw(version as *mut c_char) };
    let desc_owned = desc_cstr.map(|_d| unsafe { CString::from_raw(description as *mut c_char) });

    let meta = Box::new(FragmentMetadata {
        id: id_owned.into_raw(),
        name: name_owned.into_raw(),
        version: version_owned.into_raw(),
        description: if let Some(d) = desc_owned {
            d.into_raw()
        } else {
            ptr::null()
        },
    });

    Box::into_raw(meta)
}

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn phantom_fragment_metadata_free(meta: *mut FragmentMetadata) {
    if meta.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw((*meta).id as *mut c_char));
        drop(CString::from_raw((*meta).name as *mut c_char));
        drop(CString::from_raw((*meta).version as *mut c_char));
        if !(*meta).description.is_null() {
            drop(CString::from_raw((*meta).description as *mut c_char));
        }
        drop(Box::from_raw(meta));
    }
}

// Existing Rust types for internal use (non-FFI)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RustFragmentMetadata {
    pub id: String,
    pub name: String,
    pub version: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum FragmentState {
    Loaded,
    Running,
    Completed,
    Failed(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExecutionResult {
    pub output: String,
    pub exit_code: i32,
}

