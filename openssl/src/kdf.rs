use *;

/* KDF / PRF parameters */
pub const OSSL_KDF_PARAM_SECRET: *const u8 = b"secret\0" as *const u8;
pub const OSSL_KDF_PARAM_KEY: *const u8 = b"key\0" as *const u8;
pub const OSSL_KDF_PARAM_SALT: *const u8 = b"salt\0" as *const u8;
pub const OSSL_KDF_PARAM_PASSWORD: *const u8 = b"pass\0" as *const u8;
pub const OSSL_KDF_PARAM_DIGEST: *const u8 = OSSL_ALG_PARAM_DIGEST;
pub const OSSL_KDF_PARAM_CIPHER: *const u8 = OSSL_ALG_PARAM_CIPHER;
pub const OSSL_KDF_PARAM_MAC: *const u8 = OSSL_ALG_PARAM_MAC;
pub const OSSL_KDF_PARAM_MAC_SIZE: *const u8 = b"maclen\0" as *const u8;
pub const OSSL_KDF_PARAM_PROPERTIES: *const u8 = OSSL_ALG_PARAM_PROPERTIES;
pub const OSSL_KDF_PARAM_ITER: *const u8 = b"iter\0" as *const u8;
pub const OSSL_KDF_PARAM_MODE: *const u8 = b"mode\0" as *const u8;
pub const OSSL_KDF_PARAM_PKCS5: *const u8 = b"pkcs5\0" as *const u8;
pub const OSSL_KDF_PARAM_UKM: *const u8 = b"ukm\0" as *const u8;
pub const OSSL_KDF_PARAM_CEK_ALG: *const u8 = b"cekalg\0" as *const u8;
pub const OSSL_KDF_PARAM_SCRYPT_N: *const u8 = b"n\0" as *const u8;
pub const OSSL_KDF_PARAM_SCRYPT_R: *const u8 = b"r\0" as *const u8;
pub const OSSL_KDF_PARAM_SCRYPT_P: *const u8 = b"p\0" as *const u8;
pub const OSSL_KDF_PARAM_SCRYPT_MAXMEM: *const u8 = b"maxmem_bytes\0" as *const u8;
pub const OSSL_KDF_PARAM_INFO: *const u8 = b"info\0" as *const u8;
pub const OSSL_KDF_PARAM_SEED: *const u8 = b"seed\0" as *const u8;
pub const OSSL_KDF_PARAM_SSHKDF_XCGHASH: *const u8 = b"xcghash\0" as *const u8;
pub const OSSL_KDF_PARAM_SSHKDF_SESSION_ID: *const u8 = b"session_id\0" as *const u8;
pub const OSSL_KDF_PARAM_SSHKDF_TYPE: *const u8 = b"type\0" as *const u8;
pub const OSSL_KDF_PARAM_SIZE: *const u8 = b"size\0" as *const u8;
pub const OSSL_KDF_PARAM_CONSTANT: *const u8 = b"constant\0" as *const u8;
pub const OSSL_KDF_PARAM_PKCS12_ID: *const u8 = b"id\0" as *const u8;
pub const OSSL_KDF_PARAM_KBKDF_USE_L: *const u8 = b"use-l\0" as *const u8;
pub const OSSL_KDF_PARAM_KBKDF_USE_SEPARATOR: *const u8 = b"use-separator\0" as *const u8;
pub const OSSL_KDF_PARAM_X942_PARTYUINFO: *const u8 = b"partyu-info\0" as *const u8;
pub const OSSL_KDF_PARAM_X942_PARTYVINFO: *const u8 = b"partyv-info\0" as *const u8;
pub const OSSL_KDF_PARAM_X942_SUPP_PUBINFO: *const u8 = b"supp-pubinfo\0" as *const u8;
pub const OSSL_KDF_PARAM_X942_SUPP_PRIVINFO: *const u8 = b"supp-privinfo\0" as *const u8;
pub const OSSL_KDF_PARAM_X942_USE_KEYBITS: *const u8 = b"use-keybits\0" as *const u8;

/* Known KDF names */
pub const OSSL_KDF_NAME_HKDF: *const u8 = b"HKDF\0" as *const u8;
pub const OSSL_KDF_NAME_PBKDF2: *const u8 = b"PBKDF2\0" as *const u8;
pub const OSSL_KDF_NAME_SCRYPT: *const u8 = b"SCRYPT\0" as *const u8;
pub const OSSL_KDF_NAME_SSHKDF: *const u8 = b"SSHKDF\0" as *const u8;
pub const OSSL_KDF_NAME_SSKDF: *const u8 = b"SSKDF\0" as *const u8;
pub const OSSL_KDF_NAME_TLS1_PRF: *const u8 = b"TLS1-PRF\0" as *const u8;
pub const OSSL_KDF_NAME_X942KDF_ASN1: *const u8 = b"X942KDF-ASN1\0" as *const u8;
pub const OSSL_KDF_NAME_X942KDF_CONCAT: *const u8 = b"X942KDF-CONCAT\0" as *const u8;
pub const OSSL_KDF_NAME_X963KDF: *const u8 = b"X963KDF\0" as *const u8;
pub const OSSL_KDF_NAME_KBKDF: *const u8 = b"KBKDF\0" as *const u8;
pub const OSSL_KDF_NAME_KRB5KDF: *const u8 = b"KRB5KDF\0" as *const u8;

use libc::c_int;

use crate::hash::MessageDigest;

type Result<T> = core::result::Result<T, ErrorStack>;

foreign_type_and_impl_send_sync_kdf! {
    type CType = ffi::KDF;
    fn drop = ffi::EVP_KDF_CTX_free;

    pub struct Kdf;

    pub struct KdfRef;
}

#[allow(unused)]
#[derive(Debug)]
#[repr(i32)]
enum KdfControlOption {
    SetPass = 0x01,
    SetSalt = 0x02,
    SetIter = 0x03,
    SetMd = 0x04,
    SetKey = 0x05,
    SetMaxmemBytes = 0x06,
    SetTlsSecret = 0x07,
    ResetTlsSeed = 0x08,
    AddTlsSeed = 0x09,
    ResetHkdfInfo = 0x0a,
    AddHkdfInfo = 0x0b,
    SetHkdfMode = 0x0c,
    SetScryptN = 0x0d,
    SetScryptR = 0x0e,
    SetScryptP = 0x0f,
    SetSshkdfXcghash = 0x10,
    SetSshkdfSessionId = 0x11,
    SetSshkdfType = 0x12,
    SetKbMode = 0x13,
    SetKbMacType = 0x14,
    SetCipher = 0x15,
    SetKbInfo = 0x16,
    SetKbSeed = 0x17,
    SetKrb5kdfConstant = 0x18,
    SetSskdfInfo = 0x19,
}

#[derive(Debug)]
#[repr(i32)]
pub enum KdfKbMode {
    Counter = 0,
    Feedback = 1,
}

#[derive(Debug)]
pub enum KdfType {
    //PBKDF2,
    //SCRYPT,
    //TLS1_PRF,
    //HKDF,
    //SSHKDF,
    KeyBased,
    //KRB5KDF,
    //SS,
}

impl KdfType {
    fn type_id(&self) -> i32 {
        match self {
            KdfType::KeyBased => 1204,
        }
    }
}

#[derive(Debug)]
#[repr(i32)]
pub enum KdfMacType {
    Hmac = 0,
    Cmac = 1,
}

impl Kdf {
    pub fn new(type_: KdfType) -> Result<Self> {
        unsafe {
            let kdf = Kdf::from_ptr(cvt_p(ffi::EVP_KDF_CTX_new_id(type_.type_id()))?);
            Ok(kdf)
        }
    }

    pub fn reset(&self) {
        unsafe { ffi::EVP_KDF_reset(self.as_ptr()) }
    }

    pub fn set_kb_mode(&self, mode: KdfKbMode) -> Result<i32> {
        unsafe {
            cvt(ffi::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetKbMode as i32,
                mode as i32,
            ))
        }
    }

    pub fn set_kb_mac_type(&self, mac_type: KdfMacType) -> Result<i32> {
        unsafe {
            cvt(ffi::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetKbMacType as i32,
                mac_type as i32,
            ))
        }
    }

    pub fn set_salt(&self, salt: &[u8]) -> Result<i32> {
        unsafe {
            cvt(ffi::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetSalt as i32,
                salt.as_ptr(),
                salt.len(),
            ))
        }
    }

    pub fn set_kb_info(&self, context: &[u8]) -> Result<i32> {
        unsafe {
            cvt(ffi::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetKbInfo as i32,
                context.as_ptr(),
                context.len(),
            ))
        }
    }

    pub fn set_key(&self, key: &[u8]) -> Result<i32> {
        unsafe {
            cvt(ffi::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetKey as i32,
                key.as_ptr(),
                key.len(),
            ))
        }
    }

    pub fn set_digest(&self, digest: MessageDigest) -> Result<i32> {
        unsafe {
            cvt(ffi::EVP_KDF_ctrl(
                self.as_ptr(),
                KdfControlOption::SetMd as i32,
                digest.as_ptr(),
            ))
        }
    }

    pub fn derive(&self, key_len: usize) -> Result<Vec<u8>> {
        unsafe {
            let mut key_out: Vec<u8> = vec![0; key_len];
            cvt(ffi::EVP_KDF_derive(
                self.as_ptr(),
                key_out.as_mut_ptr(),
                key_len,
            ))?;
            Ok(key_out)
        }
    }
}

pub(crate) fn cvt_p<T>(r: *mut T) -> Result<*mut T> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

pub(crate) fn cvt(r: c_int) -> Result<c_int> {
    if r <= 0 {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}
