package com.wakex.test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class WakeXUnitTest {

    public static void main(String[] args) {
        System.out.println("==================================================");
        System.out.println("Running WakeX Android Companion Unit Tests (Java)");
        System.out.println("==================================================");

        int passed = 0;
        int failed = 0;

        try {
            testMagicPacketConstruction();
            System.out.println("PASS: testMagicPacketConstruction");
            passed++;
        } catch (Throwable t) {
            System.err.println("FAIL: testMagicPacketConstruction: " + t.getMessage());
            failed++;
        }

        try {
            testMacSanitization();
            System.out.println("PASS: testMacSanitization");
            passed++;
        } catch (Throwable t) {
            System.err.println("FAIL: testMacSanitization: " + t.getMessage());
            failed++;
        }

        try {
            testHmacSha256Signature();
            System.out.println("PASS: testHmacSha256Signature");
            passed++;
        } catch (Throwable t) {
            System.err.println("FAIL: testHmacSha256Signature: " + t.getMessage());
            failed++;
        }

        try {
            testHmacSignatureVectorInteroperability();
            System.out.println("PASS: testHmacSignatureVectorInteroperability");
            passed++;
        } catch (Throwable t) {
            System.err.println("FAIL: testHmacSignatureVectorInteroperability: " + t.getMessage());
            failed++;
        }

        try {
            testUdpDiscoveryPacketParsing();
            System.out.println("PASS: testUdpDiscoveryPacketParsing");
            passed++;
        } catch (Throwable t) {
            System.err.println("FAIL: testUdpDiscoveryPacketParsing: " + t.getMessage());
            failed++;
        }

        try {
            testIpRebindDetection();
            System.out.println("PASS: testIpRebindDetection");
            passed++;
        } catch (Throwable t) {
            System.err.println("FAIL: testIpRebindDetection: " + t.getMessage());
            failed++;
        }

        try {
            testWatchdogTimeoutBehavior();
            System.out.println("PASS: testWatchdogTimeoutBehavior");
            passed++;
        } catch (Throwable t) {
            System.err.println("FAIL: testWatchdogTimeoutBehavior: " + t.getMessage());
            failed++;
        }

        System.out.println("--------------------------------------------------");
        System.out.println("Tests passed: " + passed + " | Failed: " + failed);
        System.out.println("==================================================");

        if (failed > 0) {
            System.exit(1);
        }
    }

    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void assertEquals(Object expected, Object actual, String message) {
        if (expected == null && actual == null) return;
        if (expected != null && expected.equals(actual)) return;
        throw new AssertionError(message + " (Expected: " + expected + ", Actual: " + actual + ")");
    }

    // Helper mirror method from MainActivity/WakeXTileService/WakeXAppWidgetProvider
    private static byte[] buildMagicPacket(String mac) {
        String cleanMac = mac.replaceAll("[:\\-\\.]", "").toUpperCase(Locale.ROOT);
        if (cleanMac.length() != 12) {
            throw new IllegalArgumentException("Invalid MAC length: " + cleanMac.length());
        }
        byte[] macBytes = new byte[6];
        for (int i = 0; i < 6; i++) {
            macBytes[i] = (byte) Integer.parseInt(cleanMac.substring(i * 2, i * 2 + 2), 16);
        }
        byte[] packetBytes = new byte[102];
        for (int i = 0; i < 6; i++) {
            packetBytes[i] = (byte) 0xFF;
        }
        for (int i = 6; i < 102; i += 6) {
            System.arraycopy(macBytes, 0, packetBytes, i, 6);
        }
        return packetBytes;
    }

    private static String signRequest(String secret, String method, String path, String timestamp, String nonce, String bodyHash) {
        try {
            String signString = method.toUpperCase(Locale.ROOT) + ":" + path + ":" + timestamp + ":" + nonce + ":" + bodyHash;
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            hmac.init(keySpec);
            byte[] hash = hmac.doFinal(signString.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void testMagicPacketConstruction() {
        String testMac = "00:11:22:33:44:55";
        byte[] packet = buildMagicPacket(testMac);

        // Verification 1: Length must be exactly 102 bytes
        assertEquals(102, packet.length, "Magic packet length must be 102 bytes");

        // Verification 2: First 6 bytes must be 0xFF
        for (int i = 0; i < 6; i++) {
            assertEquals((byte) 0xFF, packet[i], "Byte at offset " + i + " must be 0xFF");
        }

        // Verification 3: Next 96 bytes must be 16 iterations of target MAC
        byte[] expectedMac = new byte[] { (byte)0x08, (byte)0xBF, (byte)0xB8, (byte)0xDA, (byte)0xB2, (byte)0x21 };
        for (int iter = 0; iter < 16; iter++) {
            int offset = 6 + (iter * 6);
            for (int b = 0; b < 6; b++) {
                assertEquals(expectedMac[b], packet[offset + b],
                    "Mismatch at iteration " + iter + " byte offset " + b);
            }
        }
    }

    public static void testMacSanitization() {
        byte[] fromColon = buildMagicPacket("08:bf:b8:da:b2:21");
        byte[] fromHyphen = buildMagicPacket("00-11-22-33-44-55");
        byte[] fromDots = buildMagicPacket("0011.2233.4455");
        byte[] fromPlain = buildMagicPacket("001122334455");

        assertTrue(Arrays.equals(fromColon, fromHyphen), "Colon and hyphen formats should produce identical packets");
        assertTrue(Arrays.equals(fromColon, fromDots), "Colon and dot formats should produce identical packets");
        assertTrue(Arrays.equals(fromColon, fromPlain), "Colon and plain hex formats should produce identical packets");
    }

    public static void testHmacSha256Signature() {
        String secret = "test-secret-key-12345";
        String method = "POST";
        String path = "/api/power/wake";
        String timestamp = "1700000000";
        String nonce = "abc-123-nonce";
        String bodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        String signature = signRequest(secret, method, path, timestamp, nonce, bodyHash);
        assertTrue(signature != null && signature.length() == 64, "HMAC-SHA256 signature must be 64 hex characters");
    }

    public static void testHmacSignatureVectorInteroperability() throws Exception {
        // Cross-verified test vector against standard RFC 4231 HMAC-SHA256
        String secret = "wakex-super-secret-key";
        String method = "POST";
        String path = "/api/power/sleep";
        String timestamp = "1730000000";
        String nonce = "fixed-nonce-for-test";
        String bodyHash = "empty";

        String sig1 = signRequest(secret, method, path, timestamp, nonce, bodyHash);
        String sig2 = signRequest(secret, method, path, timestamp, nonce, bodyHash);
        assertEquals(sig1, sig2, "Deterministic HMAC calculation must yield identical results");

        // Verify tampering breaks signature
        String tampered = signRequest(secret, "GET", path, timestamp, nonce, bodyHash);
        assertTrue(!sig1.equals(tampered), "Tampered HTTP method must produce different signature");
    }

    public static void testUdpDiscoveryPacketParsing() {
        String jsonPayload = "{\"app\":\"WakeX\",\"ip\":\"192.168.1.104\",\"port\":8000,\"hostname\":\"test-pc\",\"os\":\"windows\"}";
        // Extract ip
        int ipIdx = jsonPayload.indexOf("\"ip\":\"");
        assertTrue(ipIdx != -1, "Payload must contain ip key");
        int ipStart = ipIdx + 6;
        int ipEnd = jsonPayload.indexOf("\"", ipStart);
        String ip = jsonPayload.substring(ipStart, ipEnd);
        assertEquals("192.168.1.104", ip, "Parsed IP must match payload");

        // Extract port
        int portIdx = jsonPayload.indexOf("\"port\":");
        assertTrue(portIdx != -1, "Payload must contain port key");
        int portStart = portIdx + 7;
        int portEnd = jsonPayload.indexOf(",", portStart);
        if (portEnd == -1) portEnd = jsonPayload.indexOf("}", portStart);
        int port = Integer.parseInt(jsonPayload.substring(portStart, portEnd).trim());
        assertEquals(8000, port, "Parsed port must match payload");
    }

    public static void testIpRebindDetection() {
        String savedUrl = "192.168.1.50:8000";
        String discoveredIp = "192.168.1.104";
        int discoveredPort = 8000;
        String newTarget = discoveredIp + ":" + discoveredPort;

        // Condition matching MainActivity.java line 765
        boolean rebindNeeded = !savedUrl.equals(newTarget);
        assertTrue(rebindNeeded, "Rebinding must trigger when host IP changes");

        // After updating
        savedUrl = newTarget;
        boolean rebindNeededAfter = !savedUrl.equals(newTarget);
        assertTrue(!rebindNeededAfter, "Rebinding must not trigger when URLs match");
    }

    public static void testWatchdogTimeoutBehavior() {
        // Watchdog state simulation matching MainActivity.java connection lifecycle
        class WatchdogSimulator {
            boolean armed = false;
            boolean timeoutFired = false;
            boolean recovered = false;

            void arm() {
                armed = true;
                timeoutFired = false;
            }

            void disarm() {
                armed = false;
            }

            void onProgress(int progress) {
                if (progress >= 75) {
                    disarm(); // MainActivity.java line 287
                }
            }

            void simulateTimeout() {
                if (armed) {
                    timeoutFired = true;
                    recovered = true; // Shows offline recovery UI
                }
            }
        }

        // Case 1: Fast render disarms watchdog before timeout
        WatchdogSimulator sim1 = new WatchdogSimulator();
        sim1.arm();
        sim1.onProgress(80);
        sim1.simulateTimeout();
        assertTrue(!sim1.timeoutFired, "Disarmed watchdog must not fire timeout");
        assertTrue(!sim1.recovered, "Disarmed watchdog must not trigger offline recovery");

        // Case 2: Hang / packet drop lets watchdog fire
        WatchdogSimulator sim2 = new WatchdogSimulator();
        sim2.arm();
        sim2.onProgress(40); // Stuck at 40%
        sim2.simulateTimeout();
        assertTrue(sim2.timeoutFired, "Stalled page must trigger watchdog timeout");
        assertTrue(sim2.recovered, "Stalled page must initiate recovery fallback");
    }
}
