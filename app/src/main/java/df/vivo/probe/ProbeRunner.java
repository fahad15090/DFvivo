package df.vivo.probe;

import android.content.Context;
import android.net.IpSecAlgorithm;
import android.net.IpSecManager;
import android.net.IpSecTransform;
import android.os.Build;
import android.system.Os;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class ProbeRunner {

    private static final String NATIVE_BIN = "libdfprobe.so";
    private static final String HOOK_LIB   = "/system/lib64/libc++.so";
    private static final String HOOK_SYM   =
            "_ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEE6sentryC1ERS3_";

    public interface Reporter { void report(String s); }

    private static final class IpSecCtx {
        IpSecManager.UdpEncapsulationSocket encapSock;
        IpSecManager.SecurityParameterIndex spiObj;
        IpSecTransform transform;
        byte[] aesKey;
        int senderPort;
    }

    public static synchronized void run(Context ctx, Reporter reporter) throws Exception {
        reportDeviceInfo(reporter);

        // ---- build the test file (the app's own private file) --------------
        File probeFile = new File(ctx.getFilesDir(), "dfprobe.bin");
        byte[] pat = new byte[2 * 4096];
        for (int i = 0; i < pat.length; i++)
            pat[i] = (byte) (0x30 + (i % 64));                  // printable pattern
        for (int o = 0; o < pat.length; o += 16)
            System.arraycopy("DFPROBEORIGINAL16".getBytes(), 0, pat, o, 16);
        try (FileOutputStream fo = new FileOutputStream(probeFile, false)) {
            fo.write(pat);
            fo.getFD().sync();
        }

        IpSecCtx ip = openIpSec(ctx, reporter);
        try {
            runBinary(new File(ctx.getApplicationInfo().nativeLibraryDir, NATIVE_BIN),
                    reporter,
                    ip,
                    probeFile.getAbsolutePath());
        } finally {
            closeIpSec(ip);
        }

        // probe file removed so the next run starts from the clean pattern
        // (the page-cache copies vanish on their own; a reboot clears all state)
        try { //noinspection ResultOfMethodCallIgnored
            probeFile.delete();
        } catch (Exception ignored) {}
    }

    /** Stage-2 hook flow: mode = status | patch | unpatch | trigger | full. */
    public static synchronized void runHook(Context ctx, Reporter reporter, String mode)
            throws Exception {
        reporter.report("\n=== STAGE2 hook mode=" + mode + " ===\n");
        reportDeviceInfo(reporter);

        File stateFile = new File(ctx.getFilesDir(), "dfstate.bin");

        IpSecCtx ip = openIpSec(ctx, reporter);
        try {
            runBinary(new File(ctx.getApplicationInfo().nativeLibraryDir, NATIVE_BIN),
                    reporter,
                    ip,
                    /* probeFile */ null,
                    "--hook-mode", mode,
                    "--hook-lib", HOOK_LIB,
                    "--hook-sym", HOOK_SYM,
                    "--hook-state", stateFile.getAbsolutePath());
        } finally {
            closeIpSec(ip);
        }
    }

    private static IpSecCtx openIpSec(Context ctx, Reporter reporter) throws Exception {
        IpSecCtx ip = new IpSecCtx();
        IpSecManager ipsec =
                (IpSecManager) ctx.getSystemService(Context.IPSEC_SERVICE);
        if (ipsec == null) {
            reporter.report("RESULT: ENV-FAIL IpSecManager unavailable\n");
            throw new IllegalStateException("IpSecManager unavailable");
        }

        ip.encapSock = ipsec.openUdpEncapsulationSocket();
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        ip.spiObj = ipsec.allocateSecurityParameterIndex(loopback);

        ip.aesKey = new byte[32];
        new SecureRandom().nextBytes(ip.aesKey);

        DatagramSocket senderSock = new DatagramSocket();
        ip.senderPort = senderSock.getLocalPort();
        senderSock.close();

        ip.transform = new IpSecTransform.Builder(ctx)
                .setEncryption(new IpSecAlgorithm(IpSecAlgorithm.CRYPT_AES_CBC, ip.aesKey))
                .setIpv4Encapsulation(ip.encapSock, ip.senderPort)
                .buildTransportModeTransform(loopback, ip.spiObj);

        reporter.report("ipsec: transform built (SA inactive, encap port "
                + ip.encapSock.getPort() + ", spi 0x"
                + Integer.toHexString(ip.spiObj.getSpi()) + ")\n");
        return ip;
    }

    private static void closeIpSec(IpSecCtx ip) {
        try { if (ip.transform != null)  ip.transform.close(); }  catch (Exception ignored) {}
        try { if (ip.spiObj != null)     ip.spiObj.close(); }     catch (Exception ignored) {}
        try { if (ip.encapSock != null)  ip.encapSock.close(); }  catch (Exception ignored) {}
    }

    private static void reportDeviceInfo(Reporter reporter) {
        reporter.report("=== device ===\n");
        reporter.report("* manufacturer: " + Build.MANUFACTURER + "\n");
        reporter.report("* model: " + Build.MODEL + "\n");
        reporter.report("* device board: " + Build.BOARD + "\n");
        reporter.report("* android version: " + Build.VERSION.RELEASE + "\n");
        reporter.report("* security patch: " + Build.VERSION.SECURITY_PATCH + "\n");
        reporter.report("* kernel version: " + System.getProperty("os.version", "?") + "\n");
        reporter.report("* uid: " + Os.getuid() + "\n");
        reportFile(reporter, "/system/lib64/libc++.so", "libc++.so");
        reportFile(reporter, "/apex/com.android.runtime/bin/crash_dump64", "crash_dump64");
        reportFile(reporter, "/vendor/bin/insmod", "insmod");
        reportFile(reporter, "/sys/fs/selinux/enforce", "selinux enforce (write=0 would be permissive)");
        reporter.report("\n");
    }

    private static void reportFile(Reporter reporter, String path, String name) {
        try {
            android.system.StructStat st = Os.stat(path);
            int r = new java.io.RandomAccessFile(path, "r").read();
            reporter.report("* " + name + ": exists, size=" + st.st_size
                    + (r >= 0 ? " readable" : "") + "\n");
        } catch (Throwable t) {
            reporter.report("* " + name + ": " + t.getClass().getSimpleName()
                    + (t.getMessage() != null ? " (" + t.getMessage() + ")" : "") + "\n");
        }
    }

    private static void runBinary(File bin, Reporter reporter, IpSecCtx ip,
                                  String probeFile, String... extra) throws Exception {
        List<String> cmd = new ArrayList<>();
        cmd.add(bin.getAbsolutePath());
        cmd.add("--encap-port");  cmd.add(String.valueOf(ip.encapSock.getPort()));
        cmd.add("--sender-port"); cmd.add(String.valueOf(ip.senderPort));
        cmd.add("--spi");         cmd.add(Integer.toUnsignedString(ip.spiObj.getSpi()));
        cmd.add("--aes-key");     cmd.add(hex(ip.aesKey));
        if (probeFile != null) { cmd.add("--file"); cmd.add(probeFile); }
        for (String a : extra) cmd.add(a);

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        for (String l; (l = r.readLine()) != null; ) reporter.report(l + "\n");
        int rc = p.waitFor();
        reporter.report("[native exit code " + rc + "]\n");
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
