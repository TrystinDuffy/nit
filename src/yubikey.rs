use std::{error::Error, fmt};

use aes::{Aes128, Aes192, Aes256};
use anyhow::{bail, ensure, Context, Result};
use cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use des::TdesEde3;
use pcsc::{Card, Context as PcscContext, Protocols, Scope, ShareMode};
use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::Recipient;

pub const DEFAULT_SLOT: u8 = 0x82;

const PIV_AID: &[u8] = &[0xA0, 0x00, 0x00, 0x03, 0x08];
const ALG_X25519: u8 = 0xE1;
const SLOT_MANAGEMENT: u8 = 0x9B;
const PIN_REFERENCE: u8 = 0x80;

const INS_SELECT: u8 = 0xA4;
const INS_VERIFY: u8 = 0x20;
const INS_GENERATE_ASYMMETRIC: u8 = 0x47;
const INS_AUTHENTICATE: u8 = 0x87;
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
const TAG_METADATA_PUBLIC_KEY: u16 = 0x04;

const PIN_POLICY_ONCE: u8 = 0x02;
const TOUCH_POLICY_ALWAYS: u8 = 0x02;
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

fn status_note(status: u16) -> &'static str {
    match status {
        0x6982 => " (PIN or management-key authentication required)",
        0x6983 => " (authentication method blocked)",
        0x6985 => " (operation denied or touch timed out)",
        0x6A80 => " (invalid command data)",
        0x6A88 => " (key or object not found)",
        0x6D00 => " (instruction unsupported by this firmware)",
        status if status & 0xFFF0 == 0x63C0 => " (incorrect PIN)",
        _ => "",
    }
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

    pub fn ensure_x25519_key(&mut self, slot: u8) -> Result<Recipient> {
        ensure!(
            self.version >= [5, 7, 0],
            "YubiKey firmware {}.{}.{} does not support PIV X25519; version 5.7 or newer is required",
            self.version[0], self.version[1], self.version[2]
        );

        if let Some((algorithm, public_key)) = self.slot_metadata(slot)? {
            ensure!(
                algorithm == ALG_X25519,
                "PIV slot {slot:02x} already contains algorithm {algorithm:02x}; nit will not overwrite it"
            );
            ensure!(
                public_key.len() == 32,
                "slot {slot:02x} has an invalid X25519 public key"
            );
            return Ok(Recipient {
                serial: self.serial,
                slot,
                public_key: public_key.try_into().expect("length checked"),
            });
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
        let public_key = self.generate_x25519(slot)?;
        Ok(Recipient {
            serial: self.serial,
            slot,
            public_key,
        })
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
        let response = self.command(0, INS_AUTHENTICATE, ALG_X25519, slot, &request)?;
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

    fn slot_metadata(&self, slot: u8) -> Result<Option<(u8, Vec<u8>)>> {
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
        let public_key = find_tlv(&response, TAG_METADATA_PUBLIC_KEY)
            .context("slot metadata lacks a public key")?
            .to_vec();
        Ok(Some((algorithm, public_key)))
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

    fn generate_x25519(&self, slot: u8) -> Result<[u8; 32]> {
        let parameters = [
            tlv(TAG_GEN_ALGORITHM, &[ALG_X25519]),
            tlv(TAG_PIN_POLICY, &[PIN_POLICY_ONCE]),
            tlv(TAG_TOUCH_POLICY, &[TOUCH_POLICY_ALWAYS]),
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
            "YubiKey returned an invalid X25519 public key"
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
        ensure!(data.len() <= 255, "APDU data is too long");
        let mut apdu = Vec::with_capacity(5 + data.len());
        apdu.extend_from_slice(&[cla, ins, p1, p2]);
        if data.is_empty() {
            apdu.push(0);
        } else {
            apdu.push(data.len() as u8);
            apdu.extend_from_slice(data);
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
        let mut receive = vec![0u8; 4096];
        let response = self
            .card
            .transmit(apdu, &mut receive)
            .context("smart-card transport failed")?;
        Ok(response.to_vec())
    }
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
    fn aes_management_cipher_round_trip() {
        let key = [3u8; 24];
        let plaintext = [9u8; 16];
        let encrypted = crypt_block(0x0A, &key, &plaintext, true).unwrap();
        let decrypted = crypt_block(0x0A, &key, &encrypted, false).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }
}
