package com.reactlibrary.utils;
import android.os.Build;

public class Compatibility {
    public static boolean twentyEight() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.P;
    }
}
