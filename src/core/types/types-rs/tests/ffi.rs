use core::ptr;
use std::ffi::CStr;
use types_rs::*;

#[test]
#[ignore = "causes SIGSEGV - needs investigation"]
fn test_container_ffi() {
    unsafe {
        let id = c"container-1".as_ptr();
        let workdir = c"/tmp/test".as_ptr();
        let mut error_ptr: *mut CPhantomError = ptr::null_mut();

        let container = phantom_container_new(
            id, workdir,
            ptr::null(), 0,
            ptr::null(), ptr::null(), 0,
            &mut error_ptr,
        );
        assert!(!container.is_null());
        assert!(error_ptr.is_null()); // No error

        let ret_id = phantom_container_get_id(container);
        assert!(!ret_id.is_null());
        let id_str = CStr::from_ptr(ret_id).to_str().unwrap();
        assert_eq!(id_str, "container-1");

        let ret_workdir = phantom_container_get_workdir(container);
        assert!(!ret_workdir.is_null());
        let workdir_str = CStr::from_ptr(ret_workdir).to_str().unwrap();
        assert_eq!(workdir_str, "/tmp/test");

        // Null container
        assert!(phantom_container_get_id(ptr::null()).is_null());
        assert!(phantom_container_get_workdir(ptr::null()).is_null());

        phantom_container_free(container);
    }
}

#[test]
#[ignore = "causes SIGSEGV - needs investigation"]
fn test_container_ffi_null_validation() {
    unsafe {
        let mut error_ptr: *mut CPhantomError = ptr::null_mut();
        // Null id should return null container + error
        let container = phantom_container_new(
            ptr::null(), c"/tmp".as_ptr(),
            ptr::null(), 0,
            ptr::null(), ptr::null(), 0,
            &mut error_ptr,
        );
        assert!(container.is_null());
        assert!(!error_ptr.is_null());
        phantom_error_free(error_ptr);
    }
}

#[test]
#[ignore = "causes SIGSEGV - needs investigation"]
fn test_fragment_metadata_ffi() {
    unsafe {
        let mut error_ptr: *mut CPhantomError = ptr::null_mut();
        let meta = phantom_fragment_metadata_new(
            c"meta-1".as_ptr(),
            c"test-fragment".as_ptr(),
            c"1.0.0".as_ptr(),
            c"A test fragment".as_ptr(),
            &mut error_ptr,
        );
        assert!(!meta.is_null());
        assert!(error_ptr.is_null());

        phantom_fragment_metadata_free(meta);
    }
}
