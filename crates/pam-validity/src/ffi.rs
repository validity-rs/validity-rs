//! The C side: the two entry points libpam calls, and the four libpam
//! functions the module calls back (`pam_get_user`, `pam_get_item` for the
//! conversation, `pam_getenv`, and the conversation itself). This is the
//! crate's only unsafe code; each block says why it is sound. Everything is
//! converted to owned Rust values here, and the rest of the crate is safe.
//!
//! libpam is linked by its soname, `libpam.so.0`, so building needs the
//! runtime library only (Debian: libpam0g), not its development files.
//!
//! No panic crosses into C: [`pam_sm_authenticate`] catches any and returns
//! `PAM_AUTHINFO_UNAVAIL` (the password then decides).

#![allow(unsafe_code)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;

use crate::text::Lang;
use crate::{Talk, code};

/// `pam_handle_t`, opaque.
#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

/// `struct pam_message`.
#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

/// `struct pam_response`.
#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

/// The conversation function's type (`struct pam_conv`'s `conv`).
type ConvFn = unsafe extern "C" fn(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata_ptr: *mut c_void,
) -> c_int;

/// `struct pam_conv`.
#[repr(C)]
struct PamConv {
    conv: Option<ConvFn>,
    appdata_ptr: *mut c_void,
}

const PAM_SUCCESS: c_int = 0;
const PAM_CONV: c_int = 5;
const PAM_TEXT_INFO: c_int = 4;
const PAM_SILENT: c_int = 0x8000;

#[link(name = "libpam.so.0", kind = "dylib", modifiers = "+verbatim")]
unsafe extern "C" {
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
    -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_getenv(pamh: *mut PamHandle, name: *const c_char) -> *const c_char;
}

unsafe extern "C" {
    /// libc's, for the responses the conversation allocates.
    fn free(ptr: *mut c_void);
}

/// The application's conversation, `None` under `PAM_SILENT`.
struct Conversation {
    conv: Option<(ConvFn, *mut c_void)>,
}

impl Talk for Conversation {
    fn info(&mut self, text: &str) {
        let Some((conv, appdata)) = self.conv else {
            return;
        };
        let Ok(text) = CString::new(text) else { return };
        let message = PamMessage {
            msg_style: PAM_TEXT_INFO,
            msg: text.as_ptr(),
        };
        let mut messages: *const PamMessage = &message;
        let mut resp: *mut PamResponse = ptr::null_mut();
        // SAFETY: `conv` and `appdata` come from the application's
        // `struct pam_conv` for this handle, which libpam keeps alive for
        // the transaction. The message array (one pointer) and the string
        // outlive the call. What it returns in `resp` is null or one
        // `pam_response` the application allocated with malloc, ours to free.
        unsafe {
            conv(1, &mut messages, &mut resp, appdata);
            release(resp, free);
        }
    }
}

/// Frees one conversation response, and its string if any, with `free_fn`
/// (libc's `free`; the tests record the calls instead).
///
/// # Safety
///
/// `resp` is null, or a `pam_response` whose `resp` is null or a string,
/// both allocated for `free_fn` and not used again.
unsafe fn release(resp: *mut PamResponse, free_fn: unsafe extern "C" fn(*mut c_void)) {
    if resp.is_null() {
        return;
    }
    // SAFETY: the function's contract.
    unsafe {
        if !(*resp).resp.is_null() {
            free_fn((*resp).resp.cast());
        }
        free_fn(resp.cast());
    }
}

/// `pam_get_user`, without a prompt of ours.
///
/// # Safety
///
/// `pamh` is a live PAM handle.
unsafe fn user(pamh: *mut PamHandle) -> Option<String> {
    let mut user: *const c_char = ptr::null();
    // SAFETY: `pamh` is live (the caller's contract); `user` is a valid
    // out-pointer. On success libpam points it at a NUL-terminated string
    // it owns for the transaction, copied out before returning.
    unsafe {
        if pam_get_user(pamh, &mut user, ptr::null()) != PAM_SUCCESS || user.is_null() {
            return None;
        }
        CStr::from_ptr(user)
            .to_str()
            .ok()
            .filter(|u| !u.is_empty())
            .map(str::to_string)
    }
}

/// The application's conversation function and its data.
///
/// # Safety
///
/// `pamh` is a live PAM handle.
unsafe fn conversation(pamh: *mut PamHandle) -> Option<(ConvFn, *mut c_void)> {
    let mut item: *const c_void = ptr::null();
    // SAFETY: `pamh` is live; `item` is a valid out-pointer. The PAM_CONV
    // item, when set, is a `struct pam_conv` libpam owns for the transaction.
    unsafe {
        if pam_get_item(pamh, PAM_CONV, &mut item) != PAM_SUCCESS || item.is_null() {
            return None;
        }
        let conv = &*item.cast::<PamConv>();
        Some((conv.conv?, conv.appdata_ptr))
    }
}

/// A variable of the PAM environment.
///
/// # Safety
///
/// `pamh` is a live PAM handle.
unsafe fn pam_env(pamh: *mut PamHandle, name: &str) -> Option<String> {
    let name = CString::new(name).ok()?;
    // SAFETY: `pamh` is live; `name` is NUL-terminated. The result is null
    // or a NUL-terminated string libpam owns, copied out at once.
    unsafe {
        let value = pam_getenv(pamh, name.as_ptr());
        if value.is_null() {
            return None;
        }
        CStr::from_ptr(value).to_str().ok().map(str::to_string)
    }
}

/// The module's arguments, those that are UTF-8.
///
/// # Safety
///
/// `argv` holds `argc` pointers to NUL-terminated strings (or is null with `argc` 0).
unsafe fn args(argc: c_int, argv: *const *const c_char) -> Vec<String> {
    let Ok(n) = usize::try_from(argc) else {
        return Vec::new();
    };
    if argv.is_null() || n == 0 {
        return Vec::new();
    }
    // SAFETY: libpam passes `argc` valid pointers in `argv`, each to a
    // NUL-terminated string, for the length of the call.
    unsafe { std::slice::from_raw_parts(argv, n) }
        .iter()
        .filter(|a| !a.is_null())
        // SAFETY: as above, a non-null element is a NUL-terminated string.
        .filter_map(|a| {
            unsafe { CStr::from_ptr(*a) }
                .to_str()
                .ok()
                .map(str::to_string)
        })
        .collect()
}

/// # Safety
///
/// As [`pam_sm_authenticate`].
unsafe fn authenticate(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    if pamh.is_null() {
        return code::AUTHINFO_UNAVAIL;
    }
    // SAFETY: the caller's contract (a live handle, argc/argv as libpam
    // passes them) is what these helpers require.
    let (args, user, conv) = unsafe { (args(argc, argv), user(pamh), conversation(pamh)) };
    let (Some(user), Some(conv)) = (user, conv) else {
        return code::AUTHINFO_UNAVAIL;
    };
    let lang = Lang::of_env(
        // SAFETY: `pamh` is live for the whole call.
        |var| unsafe { pam_env(pamh, var) },
        |var| std::env::var(var).ok(),
    );
    let mut talk = Conversation {
        conv: (flags & PAM_SILENT == 0).then_some(conv),
    };
    crate::authenticate(&user, args.iter().map(String::as_str), lang, &mut talk).code()
}

/// Authenticates the user with a finger (the `auth` stack).
///
/// # Safety
///
/// Called by libpam only: `pamh` is the live handle of the transaction and
/// `argv` holds `argc` NUL-terminated strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // SAFETY: the caller's contract, passed on.
    catch_unwind(AssertUnwindSafe(|| unsafe {
        authenticate(pamh, flags, argc, argv)
    }))
    .unwrap_or(code::AUTHINFO_UNAVAIL)
}

/// No credentials to set: `PAM_SUCCESS`, as pam_fprintd.
///
/// # Safety
///
/// None needed: the arguments are not used.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        static FREED: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    }

    unsafe extern "C" fn record(p: *mut c_void) {
        FREED.with(|f| f.borrow_mut().push(p as usize));
    }

    fn freed() -> Vec<usize> {
        FREED.with(|f| std::mem::take(&mut *f.borrow_mut()))
    }

    #[test]
    fn responses_are_freed_once_with_their_string() {
        // SAFETY: `record` frees nothing; the pointers stay valid.
        unsafe { release(ptr::null_mut(), record) };
        assert_eq!(freed(), Vec::<usize>::new());

        let mut empty = PamResponse {
            resp: ptr::null_mut(),
            resp_retcode: 0,
        };
        // SAFETY: as above.
        unsafe { release(&mut empty, record) };
        assert_eq!(freed(), [&raw mut empty as usize]);

        let mut text = *b"ok\0";
        let mut full = PamResponse {
            resp: text.as_mut_ptr().cast(),
            resp_retcode: 0,
        };
        // SAFETY: as above.
        unsafe { release(&mut full, record) };
        assert_eq!(freed(), [text.as_ptr() as usize, &raw mut full as usize]);
    }
}
