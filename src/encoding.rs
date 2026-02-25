/// encoding.rs — Header format and full encode/decode pipelines
///
/// HEADER FORMAT (binary, stored inside the DNA payload)
/// ──────────────────────────────────────────────────────
///
///  Offset  Len   Field
///  ──────  ───   ─────────────────────────────────────────────────
///  0       4     Magic bytes: 0x44 0x4E 0x44 0x43  ("DNDC")
///  4       1     Version: 0x01
///  5       16    Argon2 salt  (random, 128 bits)
///  21      12    ChaCha20 nonce  (random, 96 bits)
///  33      8     Payload length (u64 little-endian, encrypted ciphertext size)
///  ──────  ───   ─────────────────────────────────────────────────
///  41      N     Ciphertext (plaintext UTF-8 encrypted with Poly1305 tag)
///
/// Total header: 41 bytes → 164 DNA bases
///
/// WHY a binary header embedded in DNA?
///   All metadata required to reconstruct the key and decrypt the payload
///   must travel with the DNA string. Embedding it as the first bytes of
///   the encoded blob means a single self-contained string is all you need.
///
/// WHY authenticated encryption covers the payload?
///   The Poly1305 MAC appended by ChaCha20-Poly1305 ensures that any
///   bit-flip in the ciphertext (accidental or malicious) is detected
///   before we attempt UTF-8 decoding. Wrong password → MAC mismatch →
///   clean "DecryptionFailed" error, never a confusing garbled output.
use crate::crypto::{
    decrypt, derive_dna_mapping, derive_keys, derive_keys_with_salt, encrypt, NONCE_LEN, SALT_LEN,
};
use crate::dna::{bytes_to_dna, dna_to_bytes, group_dna};
use crate::error::{DendecError, Result};

// Magic bytes that identify a dendec-encoded blob ("DNDC")
const MAGIC: [u8; 4] = [0x44, 0x4E, 0x44, 0x43];
const VERSION: u8 = 0x01;

/// The structured header, parsed out of raw bytes.
struct Header {
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    payload_len: u64,
}

/// Serialize a header + ciphertext into a flat byte slice.
fn build_packet(header: &Header, ciphertext: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(41 + ciphertext.len());
    packet.extend_from_slice(&MAGIC);
    packet.push(VERSION);
    packet.extend_from_slice(&header.salt);
    packet.extend_from_slice(&header.nonce);
    packet.extend_from_slice(&header.payload_len.to_le_bytes());
    packet.extend_from_slice(ciphertext);
    packet
}

/// Parse a flat byte slice into a Header + ciphertext slice.
fn parse_packet(packet: &[u8]) -> Result<(Header, &[u8])> {
    // Minimum viable packet: 41 header bytes + at least 1 ciphertext byte
    if packet.len() < 42 {
        return Err(DendecError::BadMagic);
    }

    if &packet[0..4] != MAGIC {
        return Err(DendecError::BadMagic);
    }

    let version = packet[4];
    if version != VERSION {
        return Err(DendecError::UnsupportedVersion {
            expected: VERSION,
            got: version,
        });
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&packet[5..21]);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&packet[21..33]);

    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&packet[33..41]);
    let payload_len = u64::from_le_bytes(len_bytes) as u64;

    let ciphertext = &packet[41..];

    if ciphertext.len() != payload_len as usize {
        return Err(DendecError::LengthMismatch {
            header: payload_len as usize,
            actual: ciphertext.len(),
        });
    }

    Ok((Header { salt, nonce, payload_len }, ciphertext))
}

/// Full encode pipeline:
///   text → UTF-8 bytes → encrypt → build packet → bytes_to_dna
///
/// Returns a DNA string (optionally grouped).
pub fn encode(text: &str, password: &str, group: Option<usize>) -> Result<String> {
    // Step 1: UTF-8 bytes (supports all Unicode including emoji, newlines, etc.)
    let plaintext = text.as_bytes();

    // Step 2: Derive keys (fresh random salt generated inside derive_keys)
    let keys = derive_keys(password)?;

    // Step 3: Encrypt with ChaCha20-Poly1305 (fresh random nonce inside encrypt)
    let (nonce, ciphertext) = encrypt(&keys.cipher_key, plaintext)?;

    // Step 4: Assemble header + ciphertext into a binary packet
    let header = Header {
        salt: keys.salt,
        nonce,
        payload_len: ciphertext.len() as u64,
    };
    let packet = build_packet(&header, &ciphertext);

    // Step 5: Derive the DNA base mapping from the password-derived seed
    //         WHY: makes the output alphabet itself key-dependent
    let mapping = derive_dna_mapping(keys.mapping_seed);

    // Step 6: Convert binary packet → DNA string
    let dna = bytes_to_dna(&packet, &mapping);

    // Optional: group output for human readability
    if let Some(n) = group {
        Ok(group_dna(&dna, n))
    } else {
        Ok(dna)
    }
}

/// Full decode pipeline:
///   DNA string → bytes → parse packet → derive key → decrypt → UTF-8
pub fn decode(dna: &str, password: &str) -> Result<String> {
    // Strip any whitespace/grouping separators before processing
    let dna_clean: String = dna.chars().filter(|c| !c.is_whitespace()).collect();

    // We cannot know the mapping until we have the salt, but we also can't
    // read the salt until we decode the DNA. Bootstrap solution:
    //   • The header occupies the FIRST 41 bytes → 164 bases.
    //   • We try all 24 possible base permutations on the first 164 bases
    //     to find the one that reveals valid magic bytes.
    //
    // More efficient approach used here: because the salt IS in the header,
    // we need to partially decode just enough to read the salt. We do this
    // by trying every permutation of [A,T,G,C] (only 24) on the header
    // region. Once we find the magic, we have the salt, derive the real key,
    // and proceed normally with the full sequence.

    let header_dna_len = 41 * 4; // 41 bytes × 4 bases/byte = 164 bases

    if dna_clean.len() < header_dna_len {
        return Err(DendecError::BadMagic);
    }

    let header_dna = &dna_clean[..header_dna_len];

    // Try all 24 permutations of [A, T, G, C] to find the correct mapping
    let bases = [b'A', b'T', b'G', b'C'];
    let permutations = all_permutations(&bases);

    let mut found_salt: Option<[u8; SALT_LEN]> = None;
    let mut found_mapping: Option<[u8; 4]> = None;

    'outer: for perm in &permutations {
        if let Ok(header_bytes) = dna_to_bytes(header_dna, perm) {
            if &header_bytes[0..4] == MAGIC {
                // Confirm version
                if header_bytes[4] == VERSION {
                    let mut salt = [0u8; SALT_LEN];
                    salt.copy_from_slice(&header_bytes[5..21]);
                    // Verify the derived mapping matches this permutation
                    let keys = derive_keys_with_salt(password, &salt)?;
                    let expected_mapping = derive_dna_mapping(keys.mapping_seed);
                    if expected_mapping == *perm {
                        found_salt = Some(salt);
                        found_mapping = Some(*perm);
                        break 'outer;
                    }
                }
            }
        }
    }

    let mapping = found_mapping.ok_or(DendecError::BadMagic)?;
    let salt = found_salt.unwrap();

    // Now decode the entire DNA with the confirmed mapping
    let packet = dna_to_bytes(&dna_clean, &mapping)?;

    // Parse header from packet
    let (header, ciphertext) = parse_packet(&packet)?;

    // Re-derive the full key set using the recovered salt
    let keys = derive_keys_with_salt(password, &header.salt)?;

    // Decrypt — Poly1305 MAC verification happens here
    // Wrong password → DecryptionFailed
    let plaintext = decrypt(&keys.cipher_key, &header.nonce, ciphertext)?;

    // Decode UTF-8
    let text = String::from_utf8(plaintext)?;

    Ok(text)
}

/// Generate all 24 permutations of a 4-element array.
fn all_permutations(arr: &[u8; 4]) -> Vec<[u8; 4]> {
    let mut result = Vec::with_capacity(24);
    let mut a = *arr;
    // Heap's algorithm for 4 elements
    let mut c = [0usize; 4];
    result.push(a);
    let mut i = 0;
    while i < 4 {
        if c[i] < i {
            if i % 2 == 0 {
                a.swap(0, i);
            } else {
                a.swap(c[i], i);
            }
            result.push(a);
            c[i] += 1;
            i = 0;
        } else {
            c[i] = 0;
            i += 1;
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_ascii() {
        let text = "Hello, World!";
        let password = "correct-horse-battery-staple";
        let dna = encode(text, password, None).unwrap();
        let decoded = decode(&dna, password).unwrap();
        assert_eq!(text, decoded);
    }

    #[test]
    fn test_encode_decode_emoji() {
        let text = "DNA 🧬 is cool! ✨ テスト";
        let password = "p@ssw0rd!";
        let dna = encode(text, password, None).unwrap();
        let decoded = decode(&dna, password).unwrap();
        assert_eq!(text, decoded);
    }

    #[test]
    fn test_wrong_password_fails() {
        let text = "Secret message";
        let dna = encode(text, "correct-password", None).unwrap();
        let result = decode(&dna, "wrong-password");
        assert!(
            result.is_err(),
            "Decoding with wrong password should fail"
        );
    }

    #[test]
    fn test_grouped_output_decodes() {
        let text = "grouped output test";
        let password = "testpass";
        let dna = encode(text, password, Some(10)).unwrap();
        // Grouped output should still decode correctly
        let decoded = decode(&dna, password).unwrap();
        assert_eq!(text, decoded);
    }

    #[test]
    fn test_all_permutations_count() {
        let arr = [b'A', b'T', b'G', b'C'];
        let perms = all_permutations(&arr);
        assert_eq!(perms.len(), 24);
        // All 24 should be distinct
        let mut sorted = perms.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 24);
    }

    #[test]
    fn test_different_passwords_produce_different_dna() {
        let text = "Same text";
        let dna1 = encode(text, "password1", None).unwrap();
        let dna2 = encode(text, "password2", None).unwrap();
        assert_ne!(dna1, dna2);
    }

    #[test]
    fn test_same_password_different_each_time() {
        // Due to random salt + random nonce, same password → different DNA
        let text = "Same text";
        let dna1 = encode(text, "mypassword", None).unwrap();
        let dna2 = encode(text, "mypassword", None).unwrap();
        // With overwhelming probability these differ
        assert_ne!(dna1, dna2, "Each encode should be unique due to random salt/nonce");
    }

    #[test]
    fn test_corrupted_dna_fails() {
        let text = "Integrity check";
        let mut dna = encode(text, "mypassword", None).unwrap();
        // Flip one base near the end (payload area)
        let flip_pos = dna.len() - 10;
        let bytes = unsafe { dna.as_bytes_mut() };
        bytes[flip_pos] = match bytes[flip_pos] {
            b'A' => b'T',
            b'T' => b'G',
            b'G' => b'C',
            b'C' => b'A',
            _ => b'A',
        };
        let result = decode(&dna, "mypassword");
        assert!(result.is_err(), "Corrupted DNA should fail decryption");
    }

    #[test]
    fn test_unicode_newlines_tabs() {
        let text = "Line one\n\tTabbed line\nLine three 日本語";
        let password = "unicode-test";
        let dna = encode(text, password, None).unwrap();
        let decoded = decode(&dna, password).unwrap();
        assert_eq!(text, decoded);
    }
}

