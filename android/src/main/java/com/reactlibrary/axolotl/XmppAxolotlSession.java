package com.reactlibrary.axolotl;

import android.util.Base64;
import android.util.Log;

import com.reactlibrary.storage.ProtocolStorage;

import org.whispersystems.libsignal.DuplicateMessageException;
import org.whispersystems.libsignal.InvalidKeyException;
import org.whispersystems.libsignal.InvalidKeyIdException;
import org.whispersystems.libsignal.InvalidMessageException;
import org.whispersystems.libsignal.InvalidVersionException;
import org.whispersystems.libsignal.LegacyMessageException;
import org.whispersystems.libsignal.SessionCipher;
import org.whispersystems.libsignal.SignalProtocolAddress;
import org.whispersystems.libsignal.UntrustedIdentityException;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.protocol.PreKeySignalMessage;

import java.util.Iterator;
import java.util.List;

public class XmppAxolotlSession {
    private final SessionCipher cipher;
    private final ProtocolStorage protocolStorage;
    private final SignalProtocolAddress remoteAddress;

    public XmppAxolotlSession(ProtocolStorage store, SignalProtocolAddress remoteAddress) {
        this.cipher = new SessionCipher(store, remoteAddress);
        this.remoteAddress = remoteAddress;
        this.protocolStorage = store;
    }

    public AxolotlKey processSending(byte[] outgoingMessage) {
        try {
            CiphertextMessage ciphertextMessage = cipher.encrypt(outgoingMessage);
            return new AxolotlKey(getRemoteAddress().getDeviceId(), ciphertextMessage.serialize(),ciphertextMessage.getType() == CiphertextMessage.PREKEY_TYPE);
        } catch (UntrustedIdentityException e) {
            return null;
        }
    }

    public SignalProtocolAddress getRemoteAddress() {
        return remoteAddress;
    }

    public static class AxolotlKey {
        public final byte[] key;
        public final boolean prekey;
        public final int deviceId;

        public AxolotlKey(int deviceId, byte[] key, boolean prekey) {
            this.deviceId = deviceId;
            this.key = key;
            this.prekey = prekey;
        }
    }

    byte[] processReceiving(List<AxolotlKey> possibleKeys) throws CryptoFailedException {
        byte[] plaintext = null;
        Iterator<AxolotlKey> iterator = possibleKeys.iterator();
        while (iterator.hasNext()) {
            AxolotlKey encryptedKey = iterator.next();
            if (encryptedKey.prekey) {
                try {
                    String pk = Base64.encodeToString(encryptedKey.key, Base64.NO_WRAP);
                    PreKeySignalMessage preKeySignalMessage = new PreKeySignalMessage(encryptedKey.key);
                    plaintext = cipher.decrypt(preKeySignalMessage);
                } catch (InvalidMessageException e) {
                    e.printStackTrace();
                } catch (InvalidVersionException e) {
                    e.printStackTrace();
                } catch (DuplicateMessageException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (UntrustedIdentityException e) {
                    e.printStackTrace();
                } catch (InvalidKeyIdException e) {
                    e.printStackTrace();
                } catch (LegacyMessageException e) {
                    e.printStackTrace();
                }
            }
        }
        return plaintext;
    }
}
