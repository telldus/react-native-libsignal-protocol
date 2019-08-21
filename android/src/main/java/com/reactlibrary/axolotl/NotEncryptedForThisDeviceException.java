package com.reactlibrary.axolotl;

public class NotEncryptedForThisDeviceException extends CryptoFailedException {
    public NotEncryptedForThisDeviceException() {
        super("Message was not encrypted for this device");
    }
}
