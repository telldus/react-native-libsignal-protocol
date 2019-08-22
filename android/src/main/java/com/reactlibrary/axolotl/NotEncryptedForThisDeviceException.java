package com.reactlibrary.axolotl;

public class NotEncryptedForThisDeviceException extends Exception {
    public NotEncryptedForThisDeviceException() {
        super("Message was not encrypted for this device");
    }

    public NotEncryptedForThisDeviceException(String msg, Exception e) {
        super(msg, e);
    }

    public NotEncryptedForThisDeviceException(Exception e){
        super(e);
    }
}
