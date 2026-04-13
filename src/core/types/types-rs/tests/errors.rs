use types_rs::*;

#[test]
fn test_phantom_error_variants() {
    let io_err = PhantomError::InvalidInput("test input".to_string());
    assert!(io_err.to_string().contains("test input"));

    let internal_err = PhantomError::Internal("internal failure".to_string());
    assert!(internal_err.to_string().contains("internal failure"));

    let not_found = PhantomError::FragmentNotFound("frag1".to_string());
    assert!(not_found.to_string().contains("frag1"));

    let need_sudo = PhantomError::NeedSudo;
    assert!(need_sudo.to_string().contains("sudo"));
}

#[test]
fn test_ffi_error_codes() {
    assert_eq!(PHANTOM_ERROR_SUCCESS, 0);
    assert_eq!(PHANTOM_ERROR_INVALID_INPUT, -1);
    assert_eq!(PHANTOM_ERROR_OUT_OF_MEMORY, -2);
    assert_eq!(PHANTOM_ERROR_IO, -3);
    assert_eq!(PHANTOM_ERROR_SERIALIZATION, -4);
    assert_eq!(PHANTOM_ERROR_FRAGMENT_NOT_FOUND, -5);
}

#[test]
fn test_ffi_error_roundtrip() {
    unsafe {
        let msg = c"test error message".as_ptr();
        let err_ptr = create_phantom_error(PHANTOM_ERROR_INVALID_INPUT, msg);
        assert!(!err_ptr.is_null());

        let code = phantom_error_get_code(err_ptr);
        assert_eq!(code, PHANTOM_ERROR_INVALID_INPUT);

        let msg_ptr = phantom_error_get_message(err_ptr);
        assert!(!msg_ptr.is_null());
        let msg_str = std::ffi::CStr::from_ptr(msg_ptr).to_str().unwrap();
        assert!(msg_str.contains("test error message"));

        phantom_error_free(err_ptr);
    }
}

#[test]
fn test_ffi_error_null_handling() {
    unsafe {
        assert_eq!(phantom_error_get_code(core::ptr::null()), PHANTOM_ERROR_INVALID_INPUT);
        assert!(phantom_error_get_message(core::ptr::null()).is_null());
        // Should not panic
        phantom_error_free(core::ptr::null_mut());
    }
}
