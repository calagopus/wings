use std::ffi::{OsStr, OsString};

#[cfg(unix)]
pub fn os_str_from_bytes(bytes: &[u8]) -> &OsStr {
    use std::os::unix::ffi::OsStrExt;
    OsStr::from_bytes(bytes)
}

#[cfg(not(unix))]
pub fn os_str_from_bytes(bytes: &[u8]) -> &OsStr {
    let valid = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        // SAFETY: `valid_up_to()` is the length of a valid UTF-8 prefix.
        Err(e) => unsafe {
            std::str::from_utf8_unchecked(bytes.get(..e.valid_up_to()).unwrap_or(&[]))
        },
    };
    OsStr::new(valid)
}

#[cfg(unix)]
pub fn os_string_from_bytes(bytes: Vec<u8>) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(bytes)
}

#[cfg(not(unix))]
pub fn os_string_from_bytes(bytes: Vec<u8>) -> OsString {
    OsString::from(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(unix)]
pub fn os_str_as_bytes(s: &OsStr) -> std::borrow::Cow<'_, [u8]> {
    use std::os::unix::ffi::OsStrExt;
    std::borrow::Cow::Borrowed(s.as_bytes())
}

#[cfg(not(unix))]
pub fn os_str_as_bytes(s: &OsStr) -> std::borrow::Cow<'_, [u8]> {
    match s.to_str() {
        Some(s) => std::borrow::Cow::Borrowed(s.as_bytes()),
        None => std::borrow::Cow::Owned(s.to_string_lossy().into_owned().into_bytes()),
    }
}

#[cfg(unix)]
pub fn os_string_into_bytes(s: OsString) -> Vec<u8> {
    use std::os::unix::ffi::OsStringExt;
    s.into_vec()
}

#[cfg(not(unix))]
pub fn os_string_into_bytes(s: OsString) -> Vec<u8> {
    s.to_string_lossy().into_owned().into_bytes()
}
