package edu.usc.infolab.kien.blockchaingeospatial.crypto;

import java.nio.ByteBuffer;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import at.favre.lib.bytes.Bytes;

import static edu.usc.infolab.kien.blockchaingeospatial.crypto.AuthenticatedEncryptionKeyStrength.STRENGTH_HIGH;

/**
 * Implements AES (Advanced Encryption Standard) with Galois/Counter Mode (GCM), which is a mode of
 * operation for symmetric key cryptographic block ciphers that has been widely adopted because of
 * its efficiency and performance.
 * <p>
 * Every encryption produces a new 12 byte random IV (see http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
 * because the security of GCM depends choosing a unique initialization vector for every encryption performed with the same key.
 * <p>
 * The iv, encrypted content and auth tag will be encoded to the following format:
 * <p>
 * out = byte[] {x y y y y y y y y y y y y z z z ...}
 * <p>
 * x = IV length as byte
 * y = IV bytes
 * z = content bytes (encrypted content, auth tag)
 *
 * @author Patrick Favre-Bulle
 * @since 18.12.2017
 */
@SuppressWarnings("WeakerAccess")
public final class AESGCMEncryption implements AuthenticatedEncryption {
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;

    private final SecureRandom secureRandom;
    private final Provider provider;
    private Cipher cipher;

    public AESGCMEncryption() {
        this(new SecureRandom(), null);
    }

    public AESGCMEncryption(SecureRandom secureRandom) {
        this(secureRandom, null);
    }

    public AESGCMEncryption(SecureRandom secureRandom, Provider provider) {
        this.secureRandom = secureRandom;
        this.provider = provider;
    }

    @Override
    public byte[] encrypt(byte[] rawEncryptionKey, byte[] rawData, byte[] associatedData) throws AuthenticatedEncryptionException {
        if (rawEncryptionKey.length < 16) {
            throw new IllegalArgumentException("key length must be longer than 16 bytes");
        }

        byte[] iv = null;
        byte[] encrypted = null;
        try {
            iv = new byte[IV_LENGTH_BYTE];
            secureRandom.nextBytes(iv);

            final Cipher cipherEnc = getCipher();
            cipherEnc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(rawEncryptionKey, "AES"), new GCMParameterSpec(TAG_LENGTH_BIT, iv));

            if (associatedData != null) {
                cipherEnc.updateAAD(associatedData);
            }

            encrypted = cipherEnc.doFinal(rawData);

            ByteBuffer byteBuffer = ByteBuffer.allocate(1 + iv.length + encrypted.length);
            byteBuffer.put((byte) iv.length);
            byteBuffer.put(iv);
            byteBuffer.put(encrypted);
            return byteBuffer.array();
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not encrypt", e);
        } finally {
            Bytes.wrapNullSafe(iv).mutable().secureWipe();
            Bytes.wrapNullSafe(encrypted).mutable().secureWipe();
        }
    }

    @Override
    public byte[] decrypt(byte[] rawEncryptionKey, byte[] encryptedData, byte[] associatedData) throws AuthenticatedEncryptionException {
        byte[] iv = null;
        byte[] encrypted = null;
        try {
            ByteBuffer byteBuffer = ByteBuffer.wrap(encryptedData);

            int ivLength = byteBuffer.get();
            iv = new byte[ivLength];
            byteBuffer.get(iv);
            encrypted = new byte[byteBuffer.remaining()];
            byteBuffer.get(encrypted);

            final Cipher cipherDec = getCipher();
            cipherDec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rawEncryptionKey, "AES"), new GCMParameterSpec(TAG_LENGTH_BIT, iv));
            if (associatedData != null) {
                cipherDec.updateAAD(associatedData);
            }
            return cipherDec.doFinal(encrypted);
        } catch (Exception e) {
            throw new AuthenticatedEncryptionException("could not decrypt", e);
        } finally {
            Bytes.wrapNullSafe(iv).mutable().secureWipe();
            Bytes.wrapNullSafe(encrypted).mutable().secureWipe();
        }
    }

    @Override
    public int byteSizeLength(AuthenticatedEncryptionKeyStrength keyStrengthType) {
        return keyStrengthType == STRENGTH_HIGH ? 16 : 32;
    }

    private Cipher getCipher() {
        if (cipher == null) {
            try {
                if (provider != null) {
                    cipher = Cipher.getInstance(ALGORITHM, provider);
                } else {
                    cipher = Cipher.getInstance(ALGORITHM);
                }
            } catch (Exception e) {
                throw new IllegalStateException("could not get cipher instance", e);
            }
        }
        return cipher;
    }
}
