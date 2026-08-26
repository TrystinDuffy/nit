use std::{
    error::Error,
    fmt,
    time::{Duration, Instant},
};

use aes::{Aes128, Aes192, Aes256};
use anyhow::{bail, ensure, Context, Result};
use cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use des::TdesEde3;
use pcsc::{Card, Context as PcscContext, Protocols, Scope, ShareMode};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::identity::{
    DeviceIdentity, DiscoveredIdentity, IdentityBackend, IdentityOperation, IdentitySession,
    IdentityState, VaultTrustRecord,
};

pub const ENCRYPTION_SLOT: u8 = 0x82;
pub const SIGNING_SLOT: u8 = 0x83;

const PIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08];
const ALG_ED25519: u8 = 0xE0;
const ALG_X25519: u8 = 0xE1;
const SLOT_MANAGEMENT: u8 = 0x9B;
const PIN_REFERENCE: u8 = 0x80;

const INS_SELECT: u8 = 0xA4;
const INS_VERIFY: u8 = 0x20;
const INS_GENERATE_ASYMMETRIC: u8 = 0x47;
const INS_AUTHENTICATE: u8 = 0x87;
const INS_GET_DATA: u8 = 0xCB;
const INS_PUT_DATA: u8 = 0xDB;
const INS_GET_METADATA: u8 = 0xF7;
const INS_GET_SERIAL: u8 = 0xF8;
const INS_GET_VERSION: u8 = 0xFD;
const INS_GET_RESPONSE: u8 = 0xC0;

const TAG_AUTH_WITNESS: u16 = 0x80;
const TAG_AUTH_CHALLENGE: u16 = 0x81;
const TAG_AUTH_RESPONSE: u16 = 0x82;
const TAG_AUTH_EXPONENTIATION: u16 = 0x85;
const TAG_DYN_AUTH: u16 = 0x7C;
const TAG_GEN_ALGORITHM: u16 = 0x80;
const TAG_PIN_POLICY: u16 = 0xAA;
const TAG_TOUCH_POLICY: u16 = 0xAB;
const TAG_METADATA_ALGORITHM: u16 = 0x01;
const TAG_METADATA_POLICY: u16 = 0x02;
const TAG_METADATA_PUBLIC_KEY: u16 = 0x04;
const TAG_OBJECT_ID: u16 = 0x5C;
const TAG_OBJECT_DATA: u16 = 0x53;

const PIN_POLICY_ONCE: u8 = 0x02;
const TOUCH_POLICY_NEVER: u8 = 0x01;
const TOUCH_POLICY_ALWAYS: u8 = 0x02;
const TOUCH_POLICY_CACHED: u8 = 0x03;
const TOUCH_CACHE_WINDOW: Duration = Duration::from_secs(15);
const TRUST_OBJECT_ID: &[u8] = &[0x5F, 0xC1, 0x0E];
const TRUST_RECORD_MAGIC: &[u8; 8] = b"GVTRUST1";
const MAX_TRUST_RECORDS: usize = 16;
const DEFAULT_MANAGEMENT_KEY: &[u8; 24] = b"\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08\x01\x02\x03\x04\x05\x06\x07\x08";

#[derive(Debug)]
struct PivStatus(u16);

impl fmt::Display for PivStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "YubiKey PIV command failed with status {:04X}{}",
            self.0,
            status_note(self.0)
        )
    }
}

impl Error for PivStatus {}

fn is_missing_data_object(status: u16) -> bool {
    matches!(status, 0x6A82 | 0x6A88)
}

fn status_note(status: u16) -> &'static str {
    match status {
        0x6982 => " (PIN or management-key authentication required)",
        0x6983 => " (authentication method blocked)",
        0x6985 => " (operation denied or touch timed out)",
        0x6A80 => " (invalid command data)",
        0x6A82 => " (file or data object not found)",
        0x6A88 => " (key or object not found)",
        0x6D00 => " (instruction unsupported by this firmware)",
        status if status & 0xFFF0 == 0x63C0 => " (incorrect PIN)",
        _ => "",
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SlotInfo {
    Empty,
    X25519([u8; 32]),
    Ed25519([u8; 32]),
    Other(u8),
    Unavailable(String),
}

impl SlotInfo {
    pub fn description(&self, slot: u8) -> String {
        match self {
            Self::Empty => format!("slot {slot:02X} empty"),
            Self::X25519(_) => format!("slot {slot:02X} X25519"),
            Self::Ed25519(_) => format!("slot {slot:02X} Ed25519"),
            Self::Other(algorithm) => {
                format!("slot {slot:02X} occupied by algorithm {algorithm:02X}")
            }
            Self::Unavailable(error) => format!("slot {slot:02X} unavailable: {error}"),
        }
    }

    fn public_key_for(&self, algorithm: u8) -> Option<[u8; 32]> {
        match self {
            Self::X25519(key) if algorithm == ALG_X25519 => Some(*key),
            Self::Ed25519(key) if algorithm == ALG_ED25519 => Some(*key),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceInfo {
    pub serial: u32,
    pub version: [u8; 3],
    pub encryption_slot: SlotInfo,
    pub encryption_pin_policy: Option<u8>,
    pub encryption_touch_policy: Option<u8>,
    pub signing_slot: SlotInfo,
    pub signing_pin_policy: Option<u8>,
    pub signing_touch_policy: Option<u8>,
}

struct SlotMetadata {
    algorithm: u8,
    public_key: Vec<u8>,
    pin_policy: Option<u8>,
    touch_policy: Option<u8>,
}

pub struct YubiKey {
    card: Card,
    version: [u8; 3],
    serial: u32,
}

impl YubiKey {
    pub fn open(expected_serial: Option<u32>) -> Result<Self> {
        let context = PcscContext::establish(Scope::User)
            .context("cannot access the operating system smart-card service")?;
        let readers = context
            .list_readers_owned()
            .context("cannot enumerate smart-card readers")?;
        if readers.is_empty() {
            bail!("no smart-card readers found; insert a YubiKey and try again");
        }

        let mut found: Option<Self> = None;
        let mut serials = Vec::new();
        for reader in readers {
            let Ok(card) = context.connect(&reader, ShareMode::Shared, Protocols::ANY) else {
                continue;
            };
            let Ok(candidate) = Self::from_card(card) else {
                continue;
            };
            serials.push(candidate.serial);
            if expected_serial == Some(candidate.serial) {
                return Ok(candidate);
            }
            if expected_serial.is_none() {
                if found.is_some() {
                    bail!(
                        "multiple YubiKeys are connected ({}); leave only the key to provision connected",
                        serials.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
                    );
                }
                found = Some(candidate);
            }
        }

        if let Some(serial) = expected_serial {
            if serials.is_empty() {
                bail!("no YubiKey with an enabled PIV application was found");
            }
            bail!(
                "vault needs YubiKey {serial}, but connected key serials are {}",
                serials
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        found.context("no YubiKey with an enabled PIV application was found")
    }

    pub fn list_devices() -> Result<Vec<DeviceInfo>> {
        let context = PcscContext::establish(Scope::User)
            .context("cannot access the operating system smart-card service")?;
        let readers = context
            .list_readers_owned()
            .context("cannot enumerate smart-card readers")?;
        let mut devices = Vec::new();
        for reader in readers {
            let Ok(card) = context.connect(&reader, ShareMode::Shared, Protocols::ANY) else {
                continue;
            };
            let Ok(candidate) = Self::from_card(card) else {
                continue;
            };
            let encryption_metadata = candidate.slot_metadata(ENCRYPTION_SLOT).ok().flatten();
            let encryption_pin_policy = encryption_metadata
                .as_ref()
                .and_then(|metadata| metadata.pin_policy);
            let encryption_touch_policy = encryption_metadata
                .as_ref()
                .and_then(|metadata| metadata.touch_policy);
            let encryption_slot = encryption_metadata
                .map(|metadata| slot_info(metadata, ALG_X25519))
                .unwrap_or_else(|| candidate.inspect_slot(ENCRYPTION_SLOT, ALG_X25519));
            let signing_metadata = candidate.slot_metadata(SIGNING_SLOT).ok().flatten();
            let signing_pin_policy = signing_metadata
                .as_ref()
                .and_then(|metadata| metadata.pin_policy);
            let signing_touch_policy = signing_metadata
                .as_ref()
                .and_then(|metadata| metadata.touch_policy);
            let signing_slot = signing_metadata
                .map(|metadata| slot_info(metadata, ALG_ED25519))
                .unwrap_or_else(|| candidate.inspect_slot(SIGNING_SLOT, ALG_ED25519));
            if !devices
                .iter()
                .any(|device: &DeviceInfo| device.serial == candidate.serial)
            {
                devices.push(DeviceInfo {
                    serial: candidate.serial,
                    version: candidate.version,
                    encryption_slot,
                    encryption_pin_policy,
                    encryption_touch_policy,
                    signing_slot,
                    signing_pin_policy,
                    signing_touch_policy,
                });
            }
        }
        devices.sort_by_key(|device| device.serial);
        Ok(devices)
    }

    fn from_card(card: Card) -> Result<Self> {
        let mut key = Self {
            card,
            version: [0; 3],
            serial: 0,
        };
        key.command(0, INS_SELECT, 0x04, 0x00, PIV_AID)
            .context("cannot select the PIV application")?;
        let version = key.command(0, INS_GET_VERSION, 0, 0, &[])?;
        ensure!(
            version.len() == 3,
            "YubiKey returned an invalid firmware version"
        );
        key.version.copy_from_slice(&version);
        let serial = key.command(0, INS_GET_SERIAL, 0, 0, &[])?;
        ensure!(
            !serial.is_empty() && serial.len() <= 4,
            "YubiKey returned an invalid serial"
        );
        let mut padded = [0u8; 4];
        padded[4 - serial.len()..].copy_from_slice(&serial);
        key.serial = u32::from_be_bytes(padded);
        Ok(key)
    }

    pub fn verify_pin(&mut self, pin: &str) -> Result<()> {
        ensure!(pin.is_ascii(), "PIV PIN must contain ASCII characters");
        ensure!(pin.len() <= 8, "PIV PIN cannot exceed 8 bytes");
        let mut encoded = Zeroizing::new([0xFFu8; 8]);
        encoded[..pin.len()].copy_from_slice(pin.as_bytes());
        match self.command_raw(0, INS_VERIFY, 0, PIN_REFERENCE, encoded.as_ref())? {
            (_, 0x9000) => Ok(()),
            (_, status) if status & 0xFFF0 == 0x63C0 => {
                bail!("incorrect PIV PIN; {} attempt(s) remain", status & 0x000F)
            }
            (_, 0x6983) => bail!("PIV PIN is blocked"),
            (_, status) => Err(PivStatus(status).into()),
        }
    }

    pub fn ensure_x25519_key(&mut self, slot: u8) -> Result<[u8; 32]> {
        ensure!(
            self.version >= [5, 7, 4],
            "YubiKey firmware {}.{}.{} does not support the required PIV X25519 policy; version 5.7.4 or newer is required",
            self.version[0], self.version[1], self.version[2]
        );

        if let Some(metadata) = self.slot_metadata(slot)? {
            ensure!(
                metadata.algorithm == ALG_X25519,
                "PIV slot {slot:02x} already contains algorithm {:02x}; git-vault will not overwrite it",
                metadata.algorithm
            );
            ensure!(
                metadata.public_key.len() == 32,
                "slot {slot:02x} has an invalid X25519 public key"
            );
            return Ok(metadata.public_key.try_into().expect("length checked"));
        }

        eprintln!("PIV slot {slot:02x} is empty and will receive a new X25519 key.");
        let mut input = rpassword::prompt_password(
            "PIV management key (hex; Enter uses the factory default): ",
        )
        .context("failed to read PIV management key")?;
        let management_key = if input.trim().is_empty() {
            Zeroizing::new(DEFAULT_MANAGEMENT_KEY.to_vec())
        } else {
            Zeroizing::new(hex::decode(input.trim()).context("management key is not valid hex")?)
        };
        input.zeroize();
        let management_algorithm = self.management_key_algorithm()?;
        self.authenticate_management_key(management_algorithm, &management_key)?;
        self.generate_curve25519(slot, ALG_X25519, TOUCH_POLICY_ALWAYS)
    }

    pub fn ensure_ed25519_key(&mut self, slot: u8) -> Result<[u8; 32]> {
        ensure!(
            self.version >= [5, 7, 4],
            "YubiKey firmware {}.{}.{} does not support the required PIV Ed25519 policy; version 5.7.4 or newer is required",
            self.version[0],
            self.version[1],
            self.version[2]
        );

        if let Some(metadata) = self.slot_metadata(slot)? {
            ensure!(
                metadata.algorithm == ALG_ED25519,
                "PIV slot {slot:02x} already contains algorithm {:02x}; git-vault will not overwrite it",
                metadata.algorithm
            );
            ensure!(
                metadata.public_key.len() == 32,
                "slot {slot:02x} has an invalid Ed25519 public key"
            );
            return Ok(metadata.public_key.try_into().expect("length checked"));
        }

        eprintln!("PIV slot {slot:02x} is empty and will receive a new Ed25519 key.");
        let mut input = rpassword::prompt_password(
            "PIV management key (hex; Enter uses the factory default): ",
        )
        .context("failed to read PIV management key")?;
        let management_key = if input.trim().is_empty() {
            Zeroizing::new(DEFAULT_MANAGEMENT_KEY.to_vec())
        } else {
            Zeroizing::new(hex::decode(input.trim()).context("management key is not valid hex")?)
        };
        input.zeroize();
        let management_algorithm = self.management_key_algorithm()?;
        self.authenticate_management_key(management_algorithm, &management_key)?;
        self.generate_curve25519(slot, ALG_ED25519, TOUCH_POLICY_CACHED)
    }

    pub fn sign(&mut self, slot: u8, message: &[u8; 32]) -> Result<[u8; 64]> {
        let request = tlv(
            TAG_DYN_AUTH,
            &[
                tlv(TAG_AUTH_RESPONSE, &[]),
                tlv(TAG_AUTH_CHALLENGE, message),
            ]
            .concat(),
        );
        let response = self.command(0, INS_AUTHENTICATE, ALG_ED25519, slot, &request)?;
        let dynamic =
            find_tlv(&response, TAG_DYN_AUTH).context("YubiKey signing response lacks tag 7C")?;
        let signature = find_tlv(dynamic, TAG_AUTH_RESPONSE)
            .context("YubiKey signing response lacks tag 82")?;
        ensure!(
            signature.len() == 64,
            "YubiKey returned an invalid Ed25519 signature"
        );
        Ok(signature.try_into().expect("length checked"))
    }

    pub fn agree(&mut self, slot: u8, peer_public_key: &[u8; 32]) -> Result<[u8; 32]> {
        let request = tlv(
            TAG_DYN_AUTH,
            &[
                tlv(TAG_AUTH_RESPONSE, &[]),
                tlv(TAG_AUTH_EXPONENTIATION, peer_public_key),
            ]
            .concat(),
        );
        let response =
            Zeroizing::new(self.command(0, INS_AUTHENTICATE, ALG_X25519, slot, &request)?);
        let dynamic = find_tlv(&response, TAG_DYN_AUTH)
            .context("YubiKey key-agreement response lacks tag 7C")?;
        let secret = find_tlv(dynamic, TAG_AUTH_RESPONSE)
            .context("YubiKey key-agreement response lacks tag 82")?;
        ensure!(
            secret.len() == 32,
            "YubiKey returned an invalid X25519 shared secret"
        );
        Ok(secret.try_into().expect("length checked"))
    }

    fn inspect_slot(&self, slot: u8, expected_algorithm: u8) -> SlotInfo {
        match self.slot_metadata(slot) {
            Ok(None) => SlotInfo::Empty,
            Ok(Some(metadata)) => slot_info(metadata, expected_algorithm),
            Err(error) => SlotInfo::Unavailable(format!("{error:#}")),
        }
    }

    fn slot_metadata(&self, slot: u8) -> Result<Option<SlotMetadata>> {
        let (response, status) = self.command_raw(0, INS_GET_METADATA, 0, slot, &[])?;
        if status == 0x6A88 {
            return Ok(None);
        }
        if status != 0x9000 {
            return Err(PivStatus(status).into());
        }
        let algorithm = find_tlv(&response, TAG_METADATA_ALGORITHM)
            .and_then(|value| value.first().copied())
            .context("slot metadata lacks an algorithm")?;
        let encoded_public_key = find_tlv(&response, TAG_METADATA_PUBLIC_KEY)
            .context("slot metadata lacks a public key")?;
        let public_key = parse_device_public_key(encoded_public_key)?.to_vec();
        let policy = find_tlv(&response, TAG_METADATA_POLICY);
        let pin_policy = policy.and_then(|value| value.first()).copied();
        let touch_policy = policy.and_then(|value| value.get(1)).copied();
        Ok(Some(SlotMetadata {
            algorithm,
            public_key,
            pin_policy,
            touch_policy,
        }))
    }

    fn read_trust_object(&self) -> Result<Option<Vec<u8>>> {
        let request = tlv(TAG_OBJECT_ID, TRUST_OBJECT_ID);
        let (response, status) = self.command_raw(0, INS_GET_DATA, 0x3F, 0xFF, &request)?;
        // Firmware reports an absent optional data object as either
        // FILE_NOT_FOUND or REFERENCE_DATA_NOT_FOUND depending on transport/version.
        if is_missing_data_object(status) {
            return Ok(None);
        }
        if status != 0x9000 {
            return Err(PivStatus(status).into());
        }
        Ok(Some(
            find_tlv(&response, TAG_OBJECT_DATA)
                .context("YubiKey trust object lacks tag 53")?
                .to_vec(),
        ))
    }

    fn write_trust_object(&self, data: &[u8]) -> Result<()> {
        ensure!(data.len() <= 3_000, "YubiKey trust object is too large");
        let request = [
            tlv(TAG_OBJECT_ID, TRUST_OBJECT_ID),
            tlv(TAG_OBJECT_DATA, data),
        ]
        .concat();
        self.command(0, INS_PUT_DATA, 0x3F, 0xFF, &request)?;
        Ok(())
    }

    fn authenticate_management_key_from_terminal(&self) -> Result<()> {
        let mut input = rpassword::prompt_password(
            "PIV management key for hardware checkpoint (hex; Enter uses factory default): ",
        )
        .context("failed to read PIV management key")?;
        let management_key = if input.trim().is_empty() {
            Zeroizing::new(DEFAULT_MANAGEMENT_KEY.to_vec())
        } else {
            Zeroizing::new(hex::decode(input.trim()).context("management key is not valid hex")?)
        };
        input.zeroize();
        let algorithm = self.management_key_algorithm()?;
        self.authenticate_management_key(algorithm, &management_key)
    }

    fn management_key_algorithm(&self) -> Result<u8> {
        let response = self.command(0, INS_GET_METADATA, 0, SLOT_MANAGEMENT, &[])?;
        Ok(find_tlv(&response, TAG_METADATA_ALGORITHM)
            .and_then(|value| value.first().copied())
            .unwrap_or(0x03))
    }

    fn authenticate_management_key(&self, algorithm: u8, key: &[u8]) -> Result<()> {
        let challenge_len = match algorithm {
            0x03 => 8,
            0x08 | 0x0A | 0x0C => 16,
            other => bail!("unsupported PIV management-key algorithm {other:02x}"),
        };
        let expected_key_len = match algorithm {
            0x03 | 0x0A => 24,
            0x08 => 16,
            0x0C => 32,
            _ => unreachable!(),
        };
        ensure!(
            key.len() == expected_key_len,
            "management key must be {expected_key_len} bytes for algorithm {algorithm:02x}"
        );

        let request = tlv(TAG_DYN_AUTH, &tlv(TAG_AUTH_WITNESS, &[]));
        let response = self.command(0, INS_AUTHENTICATE, algorithm, SLOT_MANAGEMENT, &request)?;
        let dynamic = find_tlv(&response, TAG_DYN_AUTH)
            .context("management authentication response lacks tag 7C")?;
        let witness = find_tlv(dynamic, TAG_AUTH_WITNESS)
            .context("management authentication response lacks tag 80")?;
        ensure!(
            witness.len() == challenge_len,
            "invalid management-key witness length"
        );
        let decrypted_witness = crypt_block(algorithm, key, witness, false)?;

        let mut challenge = Zeroizing::new(vec![0u8; challenge_len]);
        OsRng.fill_bytes(challenge.as_mut_slice());
        let request = tlv(
            TAG_DYN_AUTH,
            &[
                tlv(TAG_AUTH_WITNESS, &decrypted_witness),
                tlv(TAG_AUTH_CHALLENGE, &challenge),
            ]
            .concat(),
        );
        let response = self.command(0, INS_AUTHENTICATE, algorithm, SLOT_MANAGEMENT, &request)?;
        let dynamic = find_tlv(&response, TAG_DYN_AUTH)
            .context("management authentication response lacks tag 7C")?;
        let encrypted = find_tlv(dynamic, TAG_AUTH_RESPONSE)
            .context("management authentication response lacks tag 82")?;
        let expected = crypt_block(algorithm, key, &challenge, true)?;
        ensure!(
            bool::from(encrypted.ct_eq(expected.as_slice())),
            "incorrect PIV management key"
        );
        Ok(())
    }

    fn generate_curve25519(&self, slot: u8, algorithm: u8, touch_policy: u8) -> Result<[u8; 32]> {
        ensure!(
            matches!(algorithm, ALG_X25519 | ALG_ED25519),
            "unsupported Curve25519 algorithm"
        );
        let parameters = [
            tlv(TAG_GEN_ALGORITHM, &[algorithm]),
            tlv(TAG_PIN_POLICY, &[PIN_POLICY_ONCE]),
            tlv(TAG_TOUCH_POLICY, &[touch_policy]),
        ]
        .concat();
        let request = tlv(0xAC, &parameters);
        let response = self.command(0, INS_GENERATE_ASYMMETRIC, 0, slot, &request)?;
        let public_container =
            find_tlv(&response, 0x7F49).context("key-generation response lacks tag 7F49")?;
        let public_key = find_tlv(public_container, 0x86)
            .context("key-generation response lacks public key tag 86")?;
        ensure!(
            public_key.len() == 32,
            "YubiKey returned an invalid Curve25519 public key"
        );
        Ok(public_key.try_into().expect("length checked"))
    }

    fn command(&self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<Vec<u8>> {
        let (response, status) = self.command_raw(cla, ins, p1, p2, data)?;
        if status != 0x9000 {
            return Err(PivStatus(status).into());
        }
        Ok(response)
    }

    fn command_raw(&self, cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Result<(Vec<u8>, u16)> {
        ensure!(data.len() <= u16::MAX as usize, "APDU data is too long");
        let mut apdu = Vec::with_capacity(7 + data.len());
        apdu.extend_from_slice(&[cla, ins, p1, p2]);
        match data.len() {
            0 => apdu.push(0),
            1..=255 => {
                apdu.push(data.len() as u8);
                apdu.extend_from_slice(data);
            }
            _ => {
                apdu.push(0);
                apdu.extend_from_slice(&(data.len() as u16).to_be_bytes());
                apdu.extend_from_slice(data);
            }
        }
        let mut response = self.transmit(&apdu)?;
        let mut status = take_status(&mut response)?;
        while status & 0xFF00 == 0x6100 {
            let le = status as u8;
            let mut more = self.transmit(&[0, INS_GET_RESPONSE, 0, 0, le])?;
            status = take_status(&mut more)?;
            response.extend_from_slice(&more);
        }
        Ok((response, status))
    }

    fn transmit(&self, apdu: &[u8]) -> Result<Vec<u8>> {
        let mut receive = Zeroizing::new(vec![0u8; 4096]);
        let response = self
            .card
            .transmit(apdu, &mut receive)
            .context("smart-card transport failed")?;
        Ok(response.to_vec())
    }
}

pub struct YubiKeyBackend;

impl IdentityBackend for YubiKeyBackend {
    fn id(&self) -> &'static str {
        "yubikey"
    }

    fn discover(&self) -> Result<Vec<DiscoveredIdentity>> {
        Ok(YubiKey::list_devices()?
            .into_iter()
            .map(|device| {
                let encryption_public_key = device.encryption_slot.public_key_for(ALG_X25519);
                let signing_public_key = device.signing_slot.public_key_for(ALG_ED25519);
                let policy_error = device_policy_error(&device);
                let state = match (encryption_public_key, signing_public_key, policy_error) {
                    (Some(encryption_public_key), Some(signing_public_key), None) => {
                        IdentityState::Ready(DeviceIdentity {
                            backend: self.id().into(),
                            locator: device.serial.to_string(),
                            display_name: format!("YubiKey {}", device.serial),
                            encryption_public_key,
                            signing_public_key,
                        })
                    }
                    (_, _, Some(error)) => IdentityState::Unavailable(error),
                    _ if matches!(
                        device.encryption_slot,
                        SlotInfo::Empty | SlotInfo::X25519(_)
                    ) && matches!(
                        device.signing_slot,
                        SlotInfo::Empty | SlotInfo::Ed25519(_)
                    ) =>
                    {
                        IdentityState::Provisionable
                    }
                    _ => IdentityState::Unavailable(format!(
                        "{}; {}",
                        device.encryption_slot.description(ENCRYPTION_SLOT),
                        device.signing_slot.description(SIGNING_SLOT)
                    )),
                };
                DiscoveredIdentity {
                    backend: self.id().into(),
                    locator: device.serial.to_string(),
                    display_name: format!("YubiKey {}", device.serial),
                    detail: format!(
                        "firmware {}.{}.{}; {}; PIN {}; touch {}; {}; PIN {}; touch {}",
                        device.version[0],
                        device.version[1],
                        device.version[2],
                        device.encryption_slot.description(ENCRYPTION_SLOT),
                        pin_policy_description(device.encryption_pin_policy),
                        touch_policy_description(device.encryption_touch_policy),
                        device.signing_slot.description(SIGNING_SLOT),
                        pin_policy_description(device.signing_pin_policy),
                        touch_policy_description(device.signing_touch_policy)
                    ),
                    state,
                }
            })
            .collect())
    }

    fn provision(&self, identity: &DiscoveredIdentity) -> Result<DeviceIdentity> {
        ensure!(identity.backend == self.id(), "wrong identity backend");
        ensure!(
            identity.state.is_usable(),
            "{} cannot be provisioned: {}",
            identity.display_name,
            identity.state.description()
        );
        if let IdentityState::Ready(device) = &identity.state {
            return Ok(device.clone());
        }
        let serial = parse_locator(&identity.locator)?;
        let mut key = YubiKey::open(Some(serial))?;
        let encryption_public_key = key.ensure_x25519_key(ENCRYPTION_SLOT)?;
        let signing_public_key = key.ensure_ed25519_key(SIGNING_SLOT)?;
        Ok(DeviceIdentity {
            backend: self.id().into(),
            locator: identity.locator.clone(),
            display_name: identity.display_name.clone(),
            encryption_public_key,
            signing_public_key,
        })
    }

    fn open(&self, identity: &DiscoveredIdentity) -> Result<Box<dyn IdentitySession>> {
        let IdentityState::Ready(device) = &identity.state else {
            bail!("{} is not provisioned", identity.display_name);
        };
        let serial = parse_locator(&identity.locator)?;
        let mut key = YubiKey::open(Some(serial))?;
        ensure!(
            key.version >= [5, 7, 4],
            "YubiKey firmware must be 5.7.4 or newer"
        );
        let encryption_metadata = key
            .slot_metadata(ENCRYPTION_SLOT)?
            .context("slot 82 X25519 key is absent")?;
        ensure!(
            encryption_metadata.algorithm == ALG_X25519
                && pin_policy_is_once_or_stronger(encryption_metadata.pin_policy)
                && encryption_metadata.touch_policy == Some(TOUCH_POLICY_ALWAYS),
            "slot 82 must be X25519 with PIN-once-or-stronger and touch-always"
        );
        let signing_metadata = key
            .slot_metadata(SIGNING_SLOT)?
            .context("slot 83 Ed25519 key is absent")?;
        ensure!(
            signing_metadata.algorithm == ALG_ED25519
                && pin_policy_is_once_or_stronger(signing_metadata.pin_policy)
                && matches!(
                    signing_metadata.touch_policy,
                    Some(TOUCH_POLICY_ALWAYS) | Some(TOUCH_POLICY_CACHED)
                ),
            "slot 83 must be Ed25519 with PIN-once-or-stronger and touch-cached-or-always"
        );
        let signing_touch_policy = signing_metadata.touch_policy;
        let pin = Zeroizing::new(
            rpassword::prompt_password("PIV PIN: ").context("failed to read PIV PIN")?,
        );
        ensure!(
            !pin.is_empty(),
            "an empty PIV PIN was not sent to the YubiKey"
        );
        key.verify_pin(&pin)?;
        Ok(Box::new(YubiKeySession {
            key,
            identity: device.clone(),
            signing_touch_policy,
            last_sign: None,
        }))
    }
}

struct YubiKeySession {
    key: YubiKey,
    identity: DeviceIdentity,
    signing_touch_policy: Option<u8>,
    last_sign: Option<Instant>,
}

impl IdentitySession for YubiKeySession {
    fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    fn sign(&mut self, message: &[u8; 32]) -> Result<[u8; 64]> {
        let signature = self
            .key
            .sign(SIGNING_SLOT, message)
            .context("YubiKey did not authorize signing; touch when prompted, or quit and reopen to reverify the PIN")?;
        self.last_sign = Some(Instant::now());
        Ok(signature)
    }

    fn agree(&mut self, peer_public_key: &[u8; 32]) -> Result<[u8; 32]> {
        self.key.agree(ENCRYPTION_SLOT, peer_public_key).context(
            "YubiKey did not authorize key agreement; touch when prompted, or retry to reverify the PIN",
        )
    }

    fn read_trust_record(&mut self, vault_name: &str) -> Result<Option<VaultTrustRecord>> {
        let Some(bytes) = self.key.read_trust_object()? else {
            return Ok(None);
        };
        Ok(decode_trust_records(&bytes, &self.identity)?
            .into_iter()
            .find(|record| record.vault_name == vault_name))
    }

    fn write_trust_record(&mut self, record: &VaultTrustRecord) -> Result<()> {
        let mut records = match self.key.read_trust_object()? {
            Some(bytes) => decode_trust_records(&bytes, &self.identity)?,
            None => Vec::new(),
        };
        if let Some(existing) = records
            .iter_mut()
            .find(|existing| existing.vault_name == record.vault_name)
        {
            ensure!(
                record.membership_epoch >= existing.membership_epoch,
                "refusing to roll back the YubiKey membership checkpoint"
            );
            if record.membership_epoch == existing.membership_epoch {
                ensure!(
                    record == existing,
                    "YubiKey checkpoint conflicts with this membership epoch"
                );
                return Ok(());
            }
            *existing = record.clone();
        } else {
            ensure!(
                records.len() < MAX_TRUST_RECORDS,
                "YubiKey trust object is full ({MAX_TRUST_RECORDS} vaults); no checkpoint was evicted"
            );
            records.push(record.clone());
        }
        records.sort_by(|left, right| left.vault_name.cmp(&right.vault_name));
        let encoded = encode_trust_records(&records, &self.identity)?;
        self.key.authenticate_management_key_from_terminal()?;
        self.key.write_trust_object(&encoded)?;
        let verified = self
            .key
            .read_trust_object()?
            .context("YubiKey trust object disappeared after update")?;
        ensure!(
            decode_trust_records(&verified, &self.identity)? == records,
            "YubiKey checkpoint verification failed after write"
        );
        Ok(())
    }

    fn interaction_hint(&self, operation: IdentityOperation) -> Option<&'static str> {
        match operation {
            IdentityOperation::Sign
                if self.signing_touch_policy == Some(TOUCH_POLICY_NEVER)
                    || self.signing_touch_policy == Some(TOUCH_POLICY_CACHED)
                        && self
                            .last_sign
                            .is_some_and(|last| last.elapsed() < TOUCH_CACHE_WINDOW) =>
            {
                None
            }
            IdentityOperation::Sign => Some("Touch the YubiKey to sign the vault event…"),
            IdentityOperation::Agree => Some("Touch the YubiKey to unlock the membership epoch…"),
        }
    }
}

fn encode_trust_records(
    records: &[VaultTrustRecord],
    identity: &DeviceIdentity,
) -> Result<Vec<u8>> {
    ensure!(
        records.len() <= MAX_TRUST_RECORDS,
        "too many YubiKey trust records"
    );
    let mut output = TRUST_RECORD_MAGIC.to_vec();
    output.extend_from_slice(&identity.signing_public_key);
    output.extend_from_slice(&identity.encryption_public_key);
    output.push(records.len() as u8);
    for record in records {
        ensure!(
            !record.vault_name.is_empty() && record.vault_name.len() <= 64,
            "invalid vault name in YubiKey trust record"
        );
        output.push(record.vault_name.len() as u8);
        output.extend_from_slice(record.vault_name.as_bytes());
        output.extend_from_slice(&record.vault_id);
        output.extend_from_slice(&record.membership_epoch.to_be_bytes());
        output.extend_from_slice(&record.membership_event_hash);
        output.extend_from_slice(&record.trusted_trust_hash);
    }
    Ok(output)
}

fn decode_trust_records(bytes: &[u8], identity: &DeviceIdentity) -> Result<Vec<VaultTrustRecord>> {
    const HEADER_SIZE: usize = 8 + 32 + 32 + 1;
    const FIXED_RECORD_SIZE: usize = 32 + 8 + 32 + 32;
    ensure!(bytes.len() >= HEADER_SIZE, "truncated YubiKey trust object");
    ensure!(
        &bytes[..8] == TRUST_RECORD_MAGIC,
        "PIV object 5FC10E is occupied by unsupported data; refusing to overwrite it"
    );
    ensure!(
        bytes[8..40] == identity.signing_public_key
            && bytes[40..72] == identity.encryption_public_key,
        "YubiKey trust object belongs to a different permanent identity"
    );
    let count = bytes[72] as usize;
    ensure!(count <= MAX_TRUST_RECORDS, "too many YubiKey trust records");
    let mut records = Vec::with_capacity(count);
    let mut offset = HEADER_SIZE;
    for _ in 0..count {
        let name_length = *bytes
            .get(offset)
            .context("truncated YubiKey trust record name")? as usize;
        offset += 1;
        ensure!(
            (1..=64).contains(&name_length),
            "invalid YubiKey trust record name length"
        );
        let record_end = offset
            .checked_add(name_length + FIXED_RECORD_SIZE)
            .context("YubiKey trust record length overflow")?;
        ensure!(record_end <= bytes.len(), "truncated YubiKey trust record");
        let vault_name = String::from_utf8(bytes[offset..offset + name_length].to_vec())
            .context("YubiKey trust record name is not UTF-8")?;
        offset += name_length;
        let vault_id = bytes[offset..offset + 32]
            .try_into()
            .expect("length checked");
        offset += 32;
        let membership_epoch = u64::from_be_bytes(
            bytes[offset..offset + 8]
                .try_into()
                .expect("length checked"),
        );
        offset += 8;
        let membership_event_hash = bytes[offset..offset + 32]
            .try_into()
            .expect("length checked");
        offset += 32;
        let trusted_trust_hash = bytes[offset..offset + 32]
            .try_into()
            .expect("length checked");
        offset += 32;
        records.push(VaultTrustRecord {
            vault_name,
            vault_id,
            membership_epoch,
            membership_event_hash,
            trusted_trust_hash,
        });
    }
    ensure!(offset == bytes.len(), "trailing YubiKey trust object data");
    ensure!(
        records
            .windows(2)
            .all(|pair| pair[0].vault_name < pair[1].vault_name),
        "YubiKey trust records are not canonically ordered"
    );
    Ok(records)
}

fn device_policy_error(device: &DeviceInfo) -> Option<String> {
    if device.version < [5, 7, 4] {
        return Some(format!(
            "firmware {}.{}.{} is below the required 5.7.4",
            device.version[0], device.version[1], device.version[2]
        ));
    }
    if matches!(device.encryption_slot, SlotInfo::X25519(_)) {
        if !pin_policy_is_once_or_stronger(device.encryption_pin_policy) {
            return Some("slot 82 X25519 PIN policy is weaker than once".into());
        }
        if device.encryption_touch_policy != Some(TOUCH_POLICY_ALWAYS) {
            return Some("slot 82 X25519 must use touch-always".into());
        }
    }
    if matches!(device.signing_slot, SlotInfo::Ed25519(_)) {
        if !pin_policy_is_once_or_stronger(device.signing_pin_policy) {
            return Some("slot 83 Ed25519 PIN policy is weaker than once".into());
        }
        if !matches!(
            device.signing_touch_policy,
            Some(TOUCH_POLICY_ALWAYS) | Some(TOUCH_POLICY_CACHED)
        ) {
            return Some("slot 83 Ed25519 must use touch-cached or touch-always".into());
        }
    }
    None
}

fn pin_policy_is_once_or_stronger(policy: Option<u8>) -> bool {
    matches!(policy, Some(2..=5))
}

fn pin_policy_description(policy: Option<u8>) -> &'static str {
    match policy {
        Some(1) => "never",
        Some(2) => "once",
        Some(3) => "always",
        Some(4) => "match-once",
        Some(5) => "match-always",
        Some(_) => "unknown",
        None => "not reported",
    }
}

fn touch_policy_description(policy: Option<u8>) -> &'static str {
    match policy {
        Some(TOUCH_POLICY_NEVER) => "never",
        Some(TOUCH_POLICY_ALWAYS) => "always",
        Some(TOUCH_POLICY_CACHED) => "cached",
        Some(_) => "unknown",
        None => "not reported",
    }
}

fn slot_info(metadata: SlotMetadata, expected_algorithm: u8) -> SlotInfo {
    if metadata.public_key.len() != 32 {
        return SlotInfo::Other(metadata.algorithm);
    }
    let key: [u8; 32] = metadata.public_key.try_into().expect("length checked");
    match metadata.algorithm {
        ALG_X25519 if expected_algorithm == ALG_X25519 => SlotInfo::X25519(key),
        ALG_ED25519 if expected_algorithm == ALG_ED25519 => SlotInfo::Ed25519(key),
        _ => SlotInfo::Other(metadata.algorithm),
    }
}

fn parse_locator(locator: &str) -> Result<u32> {
    locator
        .parse()
        .with_context(|| format!("invalid YubiKey locator {locator:?}"))
}

fn parse_device_public_key(encoded: &[u8]) -> Result<&[u8]> {
    find_tlv(encoded, 0x86).context("slot metadata has an invalid public-key encoding")
}

fn take_status(response: &mut Vec<u8>) -> Result<u16> {
    ensure!(response.len() >= 2, "truncated smart-card response");
    let low = response.pop().unwrap();
    let high = response.pop().unwrap();
    Ok(u16::from_be_bytes([high, low]))
}

fn crypt_block(
    algorithm: u8,
    key: &[u8],
    input: &[u8],
    encrypt: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    macro_rules! apply {
        ($cipher:ty) => {{
            let cipher = <$cipher>::new_from_slice(key)
                .map_err(|_| anyhow::anyhow!("invalid management key length"))?;
            let mut block = GenericArray::clone_from_slice(input);
            if encrypt {
                cipher.encrypt_block(&mut block);
            } else {
                cipher.decrypt_block(&mut block);
            }
            Zeroizing::new(block.to_vec())
        }};
    }
    Ok(match algorithm {
        0x03 => apply!(TdesEde3),
        0x08 => apply!(Aes128),
        0x0A => apply!(Aes192),
        0x0C => apply!(Aes256),
        other => bail!("unsupported management-key algorithm {other:02x}"),
    })
}

fn tlv(tag: u16, value: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(value.len() + 5);
    if tag > 0xFF {
        output.extend_from_slice(&tag.to_be_bytes());
    } else {
        output.push(tag as u8);
    }
    if value.len() < 0x80 {
        output.push(value.len() as u8);
    } else if value.len() <= 0xFF {
        output.extend_from_slice(&[0x81, value.len() as u8]);
    } else {
        output.push(0x82);
        output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    }
    output.extend_from_slice(value);
    output
}

fn find_tlv(bytes: &[u8], wanted: u16) -> Option<&[u8]> {
    let mut position = 0;
    while position < bytes.len() {
        let first = *bytes.get(position)?;
        position += 1;
        let tag = if first & 0x1F == 0x1F {
            let second = *bytes.get(position)?;
            position += 1;
            u16::from_be_bytes([first, second])
        } else {
            first as u16
        };
        let first_length = *bytes.get(position)?;
        position += 1;
        let length = match first_length {
            0x00..=0x7F => first_length as usize,
            0x81 => {
                let value = *bytes.get(position)? as usize;
                position += 1;
                value
            }
            0x82 => {
                let high = *bytes.get(position)?;
                let low = *bytes.get(position + 1)?;
                position += 2;
                u16::from_be_bytes([high, low]) as usize
            }
            _ => return None,
        };
        let end = position.checked_add(length)?;
        let value = bytes.get(position..end)?;
        if tag == wanted {
            return Some(value);
        }
        position = end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlv_round_trip_handles_two_byte_tags() {
        let encoded = tlv(0x7F49, &tlv(0x86, &[7; 32]));
        let inner = find_tlv(&encoded, 0x7F49).unwrap();
        assert_eq!(find_tlv(inner, 0x86), Some([7; 32].as_slice()));
    }

    #[test]
    fn parses_x25519_key_from_slot_metadata() {
        let key = [7u8; 32];
        let encoded = tlv(TAG_METADATA_PUBLIC_KEY, &tlv(0x86, &key));
        let metadata = find_tlv(&encoded, TAG_METADATA_PUBLIC_KEY).unwrap();
        assert_eq!(parse_device_public_key(metadata).unwrap(), key);
    }

    #[test]
    fn trust_record_object_round_trip_is_identity_bound() {
        let identity = DeviceIdentity {
            backend: "test".into(),
            locator: "1".into(),
            display_name: "test".into(),
            encryption_public_key: [2; 32],
            signing_public_key: [3; 32],
        };
        let records = vec![
            VaultTrustRecord {
                vault_name: "personal".into(),
                vault_id: [4; 32],
                membership_epoch: 2,
                membership_event_hash: [5; 32],
                trusted_trust_hash: [6; 32],
            },
            VaultTrustRecord {
                vault_name: "work".into(),
                vault_id: [7; 32],
                membership_epoch: 9,
                membership_event_hash: [8; 32],
                trusted_trust_hash: [9; 32],
            },
        ];
        let encoded = encode_trust_records(&records, &identity).unwrap();
        assert_eq!(decode_trust_records(&encoded, &identity).unwrap(), records);
        let mut other = identity;
        other.signing_public_key[0] ^= 1;
        assert!(decode_trust_records(&encoded, &other).is_err());
    }

    #[test]
    fn recognizes_both_missing_data_object_statuses() {
        assert!(is_missing_data_object(0x6A82));
        assert!(is_missing_data_object(0x6A88));
        assert!(!is_missing_data_object(0x6982));
    }

    #[test]
    fn aes_management_cipher_round_trip() {
        let key = [3u8; 24];
        let plaintext = [9u8; 16];
        let encrypted = crypt_block(0x0A, &key, &plaintext, true).unwrap();
        let decrypted = crypt_block(0x0A, &key, &encrypted, false).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }
}
