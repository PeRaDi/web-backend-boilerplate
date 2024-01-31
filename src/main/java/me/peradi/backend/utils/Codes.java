package me.peradi.backend.utils;

public class Codes {

    public static String generatePasswordResetCode() {
        StringBuilder passwordResetCode = new StringBuilder();

        for (int i = 0; i < 6; i++) {
            if (i % 2 == 0)
                passwordResetCode.append((int) (Math.random() * 10));
            else
                passwordResetCode.append((char) (Math.random() * 25 + 65));
        }
        return passwordResetCode.toString();
    }
}
