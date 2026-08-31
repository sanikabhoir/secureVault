package com.securevault.util;

import java.io.*;
import java.nio.file.*;

public class FileUtil {
    public static byte[] readAll(String path) throws IOException {
        return Files.readAllBytes(Paths.get(path));
    }

    public static void writeAll(String path, byte[] data) throws IOException {
        Files.write(Paths.get(path), data);
    }

    public static DataOutputStream open(String path) throws IOException {
        return new DataOutputStream(new BufferedOutputStream(new FileOutputStream(path)));
    }

    public static DataInputStream openIn(String path) throws IOException {
        return new DataInputStream(new BufferedInputStream(new FileInputStream(path)));
    }
}
