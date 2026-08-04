package in.librefin.opensc;

import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ByteArray;
import com.github.unidbg.memory.Memory;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;

// Boots one real libSecureComponent.so copy under unidbg with RealLibraryJni's software AndroidKeyStore bridge.
final class RealLibraryBoot implements AutoCloseable {
    static final String CLS = "org/npci/upi/security/pinactivitycomponent/OfflineNativeDefenderService";

    final AndroidEmulator emulator;
    final VM vm;
    final DvmClass clazz;
    final RealLibraryJni jni;

    static {
        // Arch's system libunicorn.so.2 shadows unidbg's bundled build; load the bundled one by path.
        try {
            String res = "/natives/linux_64/libunicorn.so";
            InputStream in = RealLibraryBoot.class.getResourceAsStream(res);
            if (in != null) {
                File tmp = File.createTempFile("libunicorn", ".so");
                tmp.deleteOnExit();
                try (in; OutputStream out = new FileOutputStream(tmp)) {
                    in.transferTo(out);
                }
                System.load(tmp.getAbsolutePath());
            }
        } catch (IOException e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    RealLibraryBoot(Path so) {
        // unread by the code paths exercised here (null Context skips the branch that would check it)
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("in.librefin.opensc")
                .addBackendFactory(new Unicorn2Factory(false))
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM();
        jni = new RealLibraryJni();
        vm.setJni(jni);
        vm.setVerbose(false);
        DalvikModule dm = vm.loadLibrary(so.toFile(), true);
        dm.callJNI_OnLoad(emulator);
        clazz = vm.resolveClass(CLS);
        clazz.callStaticJniMethod(emulator, "nEnableUPILITEX()V");
    }

    byte[] sign(String data, String alias, boolean useEc) {
        DvmObject<?> r = clazz.callStaticJniMethodObject(emulator,
                "nOfflineSignWithKey(Ljava/lang/String;Ljava/lang/String;Z)[B",
                new StringObject(vm, data), new StringObject(vm, alias), useEc);
        return r instanceof ByteArray ba ? ba.getValue() : null;
    }

    boolean verify(String data, String sigB64, DvmObject<?> publicKey) {
        return clazz.callStaticJniMethodBoolean(emulator,
                "nOfflineVerifyEcSignature(Ljava/lang/String;Ljava/lang/String;Ljava/security/PublicKey;)Z",
                new StringObject(vm, data), new StringObject(vm, sigB64), publicKey);
    }

    @Override
    public void close() throws IOException {
        emulator.close();
    }
}
