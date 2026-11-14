// Copyright (c) 2026 Cloudflare, Inc.
// Licensed under the Apache 2.0 license found in the LICENSE file or at:
// https://opensource.org/licenses/Apache-2.0

//! macOS Keychain storage (`DataProtection` and `LegacyLogin`) with zero-prompt enforcement.

use std::fmt;

/// Active macOS Keychain backend observed on write.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Data protection keychain honoring `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
    DataProtection,
    /// File-based login keychain protected by ACL when entitlements are absent.
    LegacyLogin,
    /// Explicit file-backed `SecKeychain` isolated from the user's login keychain.
    ScopedFile,
}

impl Backend {
    /// Returns a stable diagnostic identifier for status and audit surfaces.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DataProtection => "data-protection-keychain",
            Self::LegacyLogin => "legacy-login-keychain",
            Self::ScopedFile => "scoped-file-keychain",
        }
    }
}

/// Metadata attributes returned when enumerating generic password items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemAttributes {
    /// `kSecAttrAccount` string.
    pub account: String,
    /// Optional `kSecAttrLabel` string (typically the relying party / site host).
    pub label: Option<String>,
    /// Optional `kSecAttrAccessible` token (e.g. `"aku"` on Data Protection Keychain).
    pub accessible: Option<String>,
}

/// Platform-neutral error returned by Keychain operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeychainOpError {
    code: i32,
    detail: String,
}

impl KeychainOpError {
    /// Constructs a Keychain error with OSStatus `code` and human-readable `detail`.
    pub fn new(code: i32, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }

    /// Returns the underlying Security.framework `OSStatus` code (`-1` off macOS).
    pub fn code(&self) -> i32 {
        self.code
    }
}

impl fmt::Display for KeychainOpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.detail)
    }
}

impl std::error::Error for KeychainOpError {}

/// Formats a `KeychainOpError` for diagnostics without leaking secret material.
pub fn describe_error(err: &KeychainOpError) -> String {
    err.detail.clone()
}

#[cfg(target_os = "macos")]
mod imp {
    use std::path::Path;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::sync::atomic::{AtomicU8, Ordering};

    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
    use core_foundation::string::CFString;
    use security_framework::base::Error as SecError;
    use security_framework::os::macos::keychain::{
        CreateOptions, KeychainSettings, KeychainUserInteractionLock, SecKeychain,
    };
    use security_framework_sys::access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
    use security_framework_sys::item::{
        kSecAttrAccount, kSecAttrLabel, kSecAttrService, kSecClass, kSecClassGenericPassword,
        kSecMatchLimit, kSecMatchLimitAll, kSecMatchSearchList, kSecReturnAttributes,
        kSecReturnData, kSecUseKeychain, kSecValueData,
    };
    use security_framework_sys::keychain_item::{SecItemCopyMatching, SecItemDelete, SecItemUpdate};

    use super::{Backend, ItemAttributes, KeychainOpError};

    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    const ERR_SEC_DUPLICATE_ITEM: i32 = -25299;
    const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;
    const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
    const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;

    const ATTR_ACCOUNT: &str = "acct";
    const ATTR_LABEL: &str = "labl";
    const ATTR_SERVICE: &str = "svce";
    const K_SEC_ATTR_ACCESSIBLE: &str = "pdmn";
    const K_SEC_USE_DATA_PROTECTION_KEYCHAIN: &str = "nleg";

    static BACKEND: AtomicU8 = AtomicU8::new(0);
    static SCOPED: OnceLock<Result<SecKeychain, KeychainOpError>> = OnceLock::new();
    static KEYCHAIN_IO_LOCK: Mutex<()> = Mutex::new(());

    fn lock_io() -> MutexGuard<'static, ()> {
        KEYCHAIN_IO_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn record_backend(backend: Backend) {
        let code = match backend {
            Backend::DataProtection => 1,
            Backend::LegacyLogin => 2,
            Backend::ScopedFile => 3,
        };
        BACKEND.store(code, Ordering::Relaxed);
    }

    pub fn backend() -> Option<Backend> {
        match BACKEND.load(Ordering::Relaxed) {
            1 => Some(Backend::DataProtection),
            2 => Some(Backend::LegacyLogin),
            3 => Some(Backend::ScopedFile),
            _ => None,
        }
    }

    pub fn install_scoped_keychain(path: &Path, password: &str) -> Result<(), KeychainOpError> {
        SCOPED
            .get_or_init(|| {
                no_prompt();
                let _guard = lock_io();
                let _ = std::fs::remove_file(path);
                let mut opts = CreateOptions::new();
                opts.password(password).prompt_user(false);
                let mut kc = opts.create(path).map_err(|e| to_op_error(&e))?;
                let mut settings = KeychainSettings::new();
                settings.set_lock_on_sleep(false);
                settings.set_lock_interval(None);
                let _ = kc.set_settings(&settings);
                Ok(kc)
            })
            .as_ref()
            .map(|_kc| ())
            .map_err(Clone::clone)
    }

    fn scoped_keychain() -> Option<&'static SecKeychain> {
        SCOPED.get().and_then(|res| res.as_ref().ok())
    }

    pub fn ensure_no_user_interaction() -> Result<(), String> {
        static ONCE: OnceLock<Result<KeychainUserInteractionLock, String>> = OnceLock::new();
        ONCE.get_or_init(|| {
            SecKeychain::disable_user_interaction()
                .map_err(|e| format!("disable keychain interaction: {e}"))
        })
        .as_ref()
        .map(|_lock| ())
        .map_err(Clone::clone)
    }

    fn no_prompt() {
        let _ = ensure_no_user_interaction();
    }

    pub fn user_interaction_allowed() -> Result<bool, String> {
        SecKeychain::user_interaction_allowed()
            .map_err(|e| format!("read keychain interaction state: {e}"))
    }

    fn wrap_cf_string(raw: core_foundation_sys::string::CFStringRef) -> CFString {
        unsafe { CFString::wrap_under_get_rule(raw) }
    }

    macro_rules! sec_cfstr {
        ($sym:ident) => {
            wrap_cf_string(unsafe { $sym })
        };
    }

    fn base_password_attributes(
        service: &str,
        account: Option<&str>,
    ) -> CFMutableDictionary<CFString, CFType> {
        let mut query = CFMutableDictionary::<CFString, CFType>::from_CFType_pairs(&[]);
        query.set(
            sec_cfstr!(kSecClass),
            sec_cfstr!(kSecClassGenericPassword).as_CFType(),
        );
        query.set(
            sec_cfstr!(kSecAttrService),
            CFString::new(service).as_CFType(),
        );
        if let Some(acct) = account {
            query.set(sec_cfstr!(kSecAttrAccount), CFString::new(acct).as_CFType());
        }
        query
    }

    fn apply_search_scope(query: &mut CFMutableDictionary<CFString, CFType>) {
        if let Some(kc) = scoped_keychain() {
            let list = CFArray::from_CFTypes(&[kc.as_CFType()]);
            query.set(sec_cfstr!(kSecMatchSearchList), list.as_CFType());
        }
    }

    fn generic_password_query(
        service: &str,
        account: Option<&str>,
    ) -> CFMutableDictionary<CFString, CFType> {
        let mut query = base_password_attributes(service, account);
        apply_search_scope(&mut query);
        query
    }

    fn data_protection_unavailable(err: &SecError) -> bool {
        matches!(
            err.code(),
            ERR_SEC_MISSING_ENTITLEMENT | ERR_SEC_NOT_AVAILABLE | ERR_SEC_INTERACTION_NOT_ALLOWED
        )
    }

    fn to_op_error(err: &SecError) -> KeychainOpError {
        let detail = match err.code() {
            ERR_SEC_ITEM_NOT_FOUND => "keychain item not found".to_string(),
            ERR_SEC_DUPLICATE_ITEM => "keychain item already exists".to_string(),
            ERR_SEC_MISSING_ENTITLEMENT => {
                "keychain item requires an entitlement this process does not have".to_string()
            }
            ERR_SEC_NOT_AVAILABLE => "keychain is not available".to_string(),
            ERR_SEC_INTERACTION_NOT_ALLOWED => "keychain interaction was not allowed".to_string(),
            code => format!("keychain error {code}: {err}"),
        };
        KeychainOpError::new(err.code(), detail)
    }

    fn delete_generic_item_unlocked(service: &str, account: &str) -> bool {
        let query = generic_password_query(service, Some(account));
        let status =
            unsafe { SecItemDelete(query.to_untyped().to_immutable().as_concrete_TypeRef()) };
        status == 0
    }

    pub fn set_generic_item(
        service: &str,
        account: &str,
        label: Option<&str>,
        data: &[u8],
    ) -> Result<(), KeychainOpError> {
        no_prompt();
        let _guard = lock_io();
        let _ = delete_generic_item_unlocked(service, account);
        if let Some(kc) = scoped_keychain() {
            return set_scoped_item(kc, service, account, label, data);
        }

        let mut attributes = base_password_attributes(service, Some(account));
        if let Some(lbl) = label {
            attributes.set(sec_cfstr!(kSecAttrLabel), CFString::new(lbl).as_CFType());
        }
        attributes.set(
            sec_cfstr!(kSecValueData),
            CFData::from_buffer(data).as_CFType(),
        );
        attributes.set(
            CFString::new(K_SEC_USE_DATA_PROTECTION_KEYCHAIN),
            CFBoolean::true_value().as_CFType(),
        );
        attributes.set(
            CFString::new(K_SEC_ATTR_ACCESSIBLE),
            sec_cfstr!(kSecAttrAccessibleWhenUnlockedThisDeviceOnly).as_CFType(),
        );

        #[allow(deprecated)]
        let first = security_framework::item::add_item(attributes.to_untyped().to_immutable());
        match first {
            Ok(()) => {
                record_backend(Backend::DataProtection);
                Ok(())
            }
            Err(err) if data_protection_unavailable(&err) => {
                set_legacy_item(service, account, label, data)
            }
            Err(err) => Err(to_op_error(&err)),
        }
    }

    fn set_scoped_item(
        kc: &SecKeychain,
        service: &str,
        account: &str,
        label: Option<&str>,
        data: &[u8],
    ) -> Result<(), KeychainOpError> {
        let mut attrs = base_password_attributes(service, Some(account));
        if let Some(lbl) = label {
            attrs.set(sec_cfstr!(kSecAttrLabel), CFString::new(lbl).as_CFType());
        }
        attrs.set(
            sec_cfstr!(kSecValueData),
            CFData::from_buffer(data).as_CFType(),
        );
        attrs.set(sec_cfstr!(kSecUseKeychain), kc.as_CFType());
        #[allow(deprecated)]
        let result = security_framework::item::add_item(attrs.to_untyped().to_immutable());
        match result {
            Ok(()) => {
                record_backend(Backend::ScopedFile);
                Ok(())
            }
            Err(err) => Err(to_op_error(&err)),
        }
    }

    fn set_legacy_item(
        service: &str,
        account: &str,
        label: Option<&str>,
        data: &[u8],
    ) -> Result<(), KeychainOpError> {
        let mut legacy = base_password_attributes(service, Some(account));
        if let Some(lbl) = label {
            legacy.set(sec_cfstr!(kSecAttrLabel), CFString::new(lbl).as_CFType());
        }
        legacy.set(
            sec_cfstr!(kSecValueData),
            CFData::from_buffer(data).as_CFType(),
        );
        #[allow(deprecated)]
        let result = security_framework::item::add_item(legacy.to_untyped().to_immutable());
        match result {
            Ok(()) => {
                record_backend(Backend::LegacyLogin);
                Ok(())
            }
            Err(err) => Err(to_op_error(&err)),
        }
    }

    pub fn get_generic_item(service: &str, account: &str) -> Option<Vec<u8>> {
        no_prompt();
        let _guard = lock_io();
        let mut query = generic_password_query(service, Some(account));
        query.set(
            sec_cfstr!(kSecReturnData),
            CFBoolean::true_value().as_CFType(),
        );

        let mut result: core_foundation_sys::base::CFTypeRef = std::ptr::null();
        let status = unsafe {
            SecItemCopyMatching(
                query.to_untyped().to_immutable().as_concrete_TypeRef(),
                &mut result,
            )
        };
        if status != 0 || result.is_null() {
            return None;
        }
        let data = unsafe {
            CFData::wrap_under_get_rule(result.cast::<core_foundation_sys::data::__CFData>())
        };
        Some(data.bytes().to_vec())
    }

    pub fn delete_generic_item(service: &str, account: &str) -> bool {
        no_prompt();
        let _guard = lock_io();
        delete_generic_item_unlocked(service, account)
    }

    pub fn update_generic_item(
        service: &str,
        account: &str,
        data: &[u8],
    ) -> Result<(), KeychainOpError> {
        no_prompt();
        let _guard = lock_io();
        let query = generic_password_query(service, Some(account));
        let mut update = CFMutableDictionary::<CFString, CFType>::from_CFType_pairs(&[]);
        update.set(
            sec_cfstr!(kSecValueData),
            CFData::from_buffer(data).as_CFType(),
        );
        let status = unsafe {
            SecItemUpdate(
                query.to_untyped().to_immutable().as_concrete_TypeRef(),
                update.to_untyped().to_immutable().as_concrete_TypeRef(),
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(to_op_error(&SecError::from_code(status)))
        }
    }

    pub fn list_generic_items(service: &str) -> Vec<ItemAttributes> {
        no_prompt();
        let _guard = lock_io();
        let mut query = generic_password_query(service, None);
        query.set(
            sec_cfstr!(kSecReturnAttributes),
            CFBoolean::true_value().as_CFType(),
        );
        query.set(
            sec_cfstr!(kSecMatchLimit),
            sec_cfstr!(kSecMatchLimitAll).as_CFType(),
        );

        let Some(array) = copy_matching_array(&query) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for item in array.iter() {
            if let Some((_, attrs)) = extract_dict_entry(item.as_CFTypeRef(), false) {
                out.push(attrs);
            }
        }
        out
    }

    pub fn list_all_generic_items() -> Vec<(String, ItemAttributes)> {
        no_prompt();
        let _guard = lock_io();
        let mut query = CFMutableDictionary::<CFString, CFType>::from_CFType_pairs(&[]);
        query.set(
            sec_cfstr!(kSecClass),
            sec_cfstr!(kSecClassGenericPassword).as_CFType(),
        );
        query.set(
            sec_cfstr!(kSecReturnAttributes),
            CFBoolean::true_value().as_CFType(),
        );
        query.set(
            sec_cfstr!(kSecMatchLimit),
            sec_cfstr!(kSecMatchLimitAll).as_CFType(),
        );
        apply_search_scope(&mut query);

        let Some(array) = copy_matching_array(&query) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for item in array.iter() {
            if let Some((Some(service), attrs)) = extract_dict_entry(item.as_CFTypeRef(), true) {
                out.push((service, attrs));
            }
        }
        out
    }

    fn copy_matching_array(
        query: &CFMutableDictionary<CFString, CFType>,
    ) -> Option<CFArray<CFType>> {
        let mut result: core_foundation_sys::base::CFTypeRef = std::ptr::null();
        let status = unsafe {
            SecItemCopyMatching(
                query.to_untyped().to_immutable().as_concrete_TypeRef(),
                &mut result,
            )
        };
        if status != 0 || result.is_null() {
            return None;
        }
        Some(unsafe {
            CFArray::<CFType>::wrap_under_create_rule(
                result.cast::<core_foundation_sys::array::__CFArray>(),
            )
        })
    }

    fn extract_dict_entry(
        item_ref: core_foundation_sys::base::CFTypeRef,
        require_service: bool,
    ) -> Option<(Option<String>, ItemAttributes)> {
        let dict = unsafe {
            CFDictionary::<CFType, CFType>::wrap_under_get_rule(
                item_ref.cast::<core_foundation_sys::dictionary::__CFDictionary>(),
            )
        };
        let mut account = None;
        let mut label = None;
        let mut service = None;
        let mut accessible = None;
        let cf_string_type_id = CFString::type_id();
        let (keys, values) = dict.get_keys_and_values();
        for (k_ptr, v_ptr) in keys.iter().zip(values.iter()) {
            if k_ptr.is_null() || v_ptr.is_null() {
                continue;
            }
            let key_tid = unsafe { core_foundation_sys::base::CFGetTypeID(*k_ptr) };
            if key_tid != cf_string_type_id {
                continue;
            }
            let key = unsafe { CFString::wrap_under_get_rule((*k_ptr).cast()) }.to_string();
            if !matches!(
                key.as_str(),
                ATTR_ACCOUNT | ATTR_LABEL | ATTR_SERVICE | K_SEC_ATTR_ACCESSIBLE
            ) {
                continue;
            }
            let val_tid = unsafe { core_foundation_sys::base::CFGetTypeID(*v_ptr) };
            if val_tid != cf_string_type_id {
                continue;
            }
            let val = unsafe { CFString::wrap_under_get_rule((*v_ptr).cast()) }.to_string();
            match key.as_str() {
                ATTR_ACCOUNT => account = Some(val),
                ATTR_LABEL => label = Some(val),
                ATTR_SERVICE => service = Some(val),
                K_SEC_ATTR_ACCESSIBLE => accessible = Some(val),
                _ => {}
            }
        }
        let acct = account?;
        if require_service && service.is_none() {
            return None;
        }
        Some((
            service,
            ItemAttributes {
                account: acct,
                label,
                accessible,
            },
        ))
    }

    pub fn is_available() -> bool {
        no_prompt();
        let probe_service = "ai.parawing.authority.keychain.probe";
        let probe_account = "availability";
        match set_generic_item(probe_service, probe_account, Some("probe"), b"probe") {
            Ok(()) => {
                let _ = delete_generic_item(probe_service, probe_account);
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use std::path::Path;

    use super::{Backend, ItemAttributes, KeychainOpError};

    fn unsupported() -> KeychainOpError {
        KeychainOpError::new(-1, "macOS Keychain is not available on this platform")
    }

    pub fn backend() -> Option<Backend> {
        None
    }

    pub fn install_scoped_keychain(_path: &Path, _password: &str) -> Result<(), KeychainOpError> {
        Err(unsupported())
    }

    pub fn ensure_no_user_interaction() -> Result<(), String> {
        Ok(())
    }

    pub fn user_interaction_allowed() -> Result<bool, String> {
        Ok(false)
    }

    pub fn set_generic_item(
        _service: &str,
        _account: &str,
        _label: Option<&str>,
        _data: &[u8],
    ) -> Result<(), KeychainOpError> {
        Err(unsupported())
    }

    pub fn get_generic_item(_service: &str, _account: &str) -> Option<Vec<u8>> {
        None
    }

    pub fn delete_generic_item(_service: &str, _account: &str) -> bool {
        false
    }

    pub fn update_generic_item(
        _service: &str,
        _account: &str,
        _data: &[u8],
    ) -> Result<(), KeychainOpError> {
        Err(unsupported())
    }

    pub fn list_generic_items(_service: &str) -> Vec<ItemAttributes> {
        Vec::new()
    }

    pub fn list_all_generic_items() -> Vec<(String, ItemAttributes)> {
        Vec::new()
    }

    pub fn is_available() -> bool {
        false
    }
}

/// Reports which Keychain backend is active.
pub fn backend() -> Option<Backend> {
    imp::backend()
}

/// Installs an isolated file-backed `SecKeychain` for this process without UI prompts.
pub fn install_scoped_keychain(
    path: &std::path::Path,
    password: &str,
) -> Result<(), KeychainOpError> {
    imp::install_scoped_keychain(path, password)
}

/// Disables interactive macOS Keychain password prompts for the lifetime of the process.
pub fn ensure_no_user_interaction() -> Result<(), String> {
    imp::ensure_no_user_interaction()
}

/// Reports whether interactive Keychain UI prompts are currently allowed.
pub fn user_interaction_allowed() -> Result<bool, String> {
    imp::user_interaction_allowed()
}

/// Writes or replaces a generic password item under `(service, account)`.
pub fn set_generic_item(
    service: &str,
    account: &str,
    label: Option<&str>,
    data: &[u8],
) -> Result<(), KeychainOpError> {
    imp::set_generic_item(service, account, label, data)
}

/// Reads the raw secret bytes of a generic password item under `(service, account)`.
pub fn get_generic_item(service: &str, account: &str) -> Option<Vec<u8>> {
    imp::get_generic_item(service, account)
}

/// Deletes a generic password item and returns true only when removal was confirmed.
pub fn delete_generic_item(service: &str, account: &str) -> bool {
    imp::delete_generic_item(service, account)
}

/// Updates the value payload of an existing generic password item in place.
pub fn update_generic_item(
    service: &str,
    account: &str,
    data: &[u8],
) -> Result<(), KeychainOpError> {
    imp::update_generic_item(service, account, data)
}

/// Lists item attributes for all generic password entries under `service`.
pub fn list_generic_items(service: &str) -> Vec<ItemAttributes> {
    imp::list_generic_items(service)
}

/// Lists `(service, attributes)` across all accessible generic password items.
pub fn list_all_generic_items() -> Vec<(String, ItemAttributes)> {
    imp::list_all_generic_items()
}

/// Probes whether the platform Keychain is reachable and writable without UI prompts.
pub fn is_available() -> bool {
    imp::is_available()
}

#[cfg(all(test, target_os = "macos"))]
pub(crate) fn ensure_test_keychain() {
    ensure_no_user_interaction().expect("disable keychain interaction");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "parawing-authority-selftest-{}-{}.keychain-db",
        std::process::id(),
        nanos,
    ));
    install_scoped_keychain(&path, "parawing-authority-selftest-pw")
        .expect("create scoped macOS SecKeychain");
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;

    fn no_prompt() {
        ensure_test_keychain();
    }

    fn service_for(test: &str) -> String {
        format!(
            "ai.parawing.authority.keychain.selftest.{}.{}",
            std::process::id(),
            test
        )
    }

    #[test]
    fn round_trips_a_generic_item() {
        no_prompt();
        let service = service_for("alice");
        set_generic_item(&service, "alice", Some("example.com"), b"s3cret")
            .expect("keychain write");
        let read = get_generic_item(&service, "alice").expect("keychain read");
        assert_eq!(read, b"s3cret");
        assert!(delete_generic_item(&service, "alice"));
        assert!(get_generic_item(&service, "alice").is_none());
    }

    #[test]
    fn overwrites_an_existing_item() {
        no_prompt();
        let service = service_for("bob");
        set_generic_item(&service, "bob", Some("example.com"), b"first").unwrap();
        set_generic_item(&service, "bob", Some("example.com"), b"second").unwrap();
        assert_eq!(get_generic_item(&service, "bob").unwrap(), b"second");
        delete_generic_item(&service, "bob");
    }

    #[test]
    fn enumerates_items_by_service() {
        no_prompt();
        let service = service_for("carol");
        set_generic_item(&service, "carol", Some("site-a.test"), b"x").unwrap();
        set_generic_item(&service, "dave", Some("site-b.test"), b"y").unwrap();
        let items = list_generic_items(&service);
        let accounts: Vec<&str> = items.iter().map(|i| i.account.as_str()).collect();
        assert!(accounts.contains(&"carol"));
        assert!(accounts.contains(&"dave"));
        let carol = items.iter().find(|i| i.account == "carol").unwrap();
        assert_eq!(carol.label.as_deref(), Some("site-a.test"));
        delete_generic_item(&service, "carol");
        delete_generic_item(&service, "dave");
    }

    #[test]
    fn updating_replaces_the_stored_data() {
        no_prompt();
        let service = service_for("erin");
        set_generic_item(&service, "erin", Some("site.test"), b"old").unwrap();
        update_generic_item(&service, "erin", b"new").unwrap();
        assert_eq!(get_generic_item(&service, "erin").unwrap(), b"new");
        delete_generic_item(&service, "erin");
    }

    #[test]
    fn deleting_a_missing_item_reports_false() {
        no_prompt();
        assert!(!delete_generic_item(&service_for("nobody"), "nobody"));
    }

    #[test]
    fn round_trips_the_accessible_attribute() {
        no_prompt();
        let service = service_for("frank");
        set_generic_item(&service, "frank", Some("site.test"), b"v").unwrap();
        let items = list_generic_items(&service);
        let item = items
            .iter()
            .find(|i| i.account == "frank")
            .expect("item must be enumerable");
        match backend() {
            Some(Backend::DataProtection) => {
                assert_eq!(item.accessible.as_deref(), Some("aku"));
            }
            Some(Backend::LegacyLogin | Backend::ScopedFile) => {
                assert_eq!(item.accessible, None);
            }
            None => panic!("write must determine active keychain backend"),
        }
        delete_generic_item(&service, "frank");
    }

    #[test]
    fn stores_binary_data_intact() {
        no_prompt();
        let service = service_for("grace");
        let payload: Vec<u8> = (0..=255u8).collect();
        set_generic_item(&service, "grace", Some("site.test"), &payload).unwrap();
        assert_eq!(get_generic_item(&service, "grace").unwrap(), payload);
        delete_generic_item(&service, "grace");
    }

    #[test]
    fn keychain_user_interaction_is_switched_off() {
        ensure_no_user_interaction().expect("disable keychain interaction");
        assert!(!user_interaction_allowed().expect("read interaction state"));
    }

    fn pid_is_dead(pid: u32) -> bool {
        if pid == 0 {
            return true;
        }
        extern "C" {
            fn kill(pid: i32, sig: i32) -> i32;
            fn __error() -> *mut i32;
        }
        // SAFETY: kill(pid, 0) checks process existence without delivering a signal.
        let rc = unsafe { kill(pid as i32, 0) };
        if rc == 0 {
            return false;
        }
        // SAFETY: __error() returns the thread-local errno pointer on macOS libSystem.
        let errno = unsafe { *__error() };
        errno == 3
    }

    fn is_stale_selftest_service(service: &str, my_pid: u32) -> bool {
        if service == format!("ai.parawing.authority.keychain.selftest.0.{my_pid}") {
            return true;
        }
        let Some(rest) = service.strip_prefix("ai.parawing.authority.keychain.selftest.") else {
            return false;
        };
        let parts: Vec<&str> = rest.split('.').collect();
        match parts.as_slice() {
            ["0", owner] => owner
                .parse::<u32>()
                .is_ok_and(|pid| pid != my_pid && pid_is_dead(pid)),
            [pid_str, ..] => pid_str
                .parse::<u32>()
                .is_ok_and(|pid| pid != my_pid && pid_is_dead(pid)),
            [] => true,
        }
    }

    #[test]
    fn cleans_up_stale_selftest_items() {
        no_prompt();
        let my_pid = std::process::id();
        let stale_svc = format!("ai.parawing.authority.keychain.selftest.0.{my_pid}");
        set_generic_item(&stale_svc, "orphan", Some("stale.test"), b"stale").unwrap();
        for (service, attributes) in list_all_generic_items() {
            if is_stale_selftest_service(&service, my_pid) {
                let _ = delete_generic_item(&service, &attributes.account);
            }
        }
        assert!(get_generic_item(&stale_svc, "orphan").is_none());
    }
}

#[cfg(all(test, not(target_os = "macos")))]
mod non_macos_tests {
    use super::*;

    #[test]
    fn fails_closed_when_platform_keychain_is_unavailable() {
        assert!(!is_available());
        assert!(backend().is_none());
        assert!(set_generic_item("svc", "acct", None, b"secret").is_err());
        assert!(get_generic_item("svc", "acct").is_none());
        assert!(!delete_generic_item("svc", "acct"));
    }
}
