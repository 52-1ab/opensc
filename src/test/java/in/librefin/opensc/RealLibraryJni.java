package in.librefin.opensc;

import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.linux.android.dvm.array.ByteArray;

import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

// Real AndroidKeyStore/Signature JNI bridge, software-backed like secure_component.c, scoped to what sign/verify call.
class RealLibraryJni extends AbstractJni {

    private final Map<String, AliasKeys> keyStoreAliases = new HashMap<>();

    private static final class AliasKeys {
        final KeyPair rsa = generateKeyPair("RSA");
        final KeyPair ec = generateKeyPair("EC");

        KeyPair forAlgorithm(String algorithm) {
            return algorithm != null && algorithm.contains("ECDSA") ? ec : rsa;
        }
    }

    private static KeyPair generateKeyPair(String algorithm) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
            if ("EC".equals(algorithm)) {
                kpg.initialize(new ECGenParameterSpec("secp256r1"));
            } else {
                kpg.initialize(2048);
            }
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(algorithm + " keygen unavailable", e);
        }
    }

    private AliasKeys keyPairFor(String alias) {
        return keyStoreAliases.computeIfAbsent(alias, a -> new AliasKeys());
    }

    // Test-only escape hatch: the real 3-native surface has no way to expose a public key.
    PublicKey publicKeyFor(String alias, String algorithm) {
        return keyPairFor(alias).forAlgorithm(algorithm).getPublic();
    }

    private static Key resolveSignKey(Object value, String algorithm) {
        if (value instanceof AliasKeys keys) {
            return keys.forAlgorithm(algorithm).getPrivate();
        }
        return (Key) value;
    }

    private static Key resolveVerifyKey(Object value, String algorithm) {
        if (value instanceof AliasKeys keys) {
            return keys.forAlgorithm(algorithm).getPublic();
        }
        return (Key) value;
    }

    // "SHAxxxwithRSA/PSS" has no JCA alias; translate to RSASSA-PSS with saltLen=digest length.
    private static Signature signatureFor(String androidAlgorithm) throws Exception {
        if (androidAlgorithm != null && androidAlgorithm.matches("SHA\\d+withRSA/PSS")) {
            String digest = "SHA-" + androidAlgorithm.replaceAll("SHA(\\d+)withRSA/PSS", "$1");
            int saltLen = MessageDigest.getInstance(digest).getDigestLength();
            Signature s = Signature.getInstance("RSASSA-PSS");
            s.setParameter(new PSSParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), saltLen, 1));
            return s;
        }
        return Signature.getInstance(androidAlgorithm);
    }

    private static final class SignatureState {
        String algorithm;
        Object signKey;
        Object verifyKey;
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    }

    private static byte[] argBytes(VaList vaList, int index) {
        DvmObject<?> arg = vaList.getObjectArg(index);
        return arg instanceof ByteArray array ? array.getValue() : null;
    }

    private static final Map<String, String> KEY_PROPERTIES_STRINGS = Map.of(
            "android/security/keystore/KeyProperties->DIGEST_SHA256:Ljava/lang/String;", "SHA-256",
            "android/security/keystore/KeyProperties->DIGEST_SHA1:Ljava/lang/String;", "SHA-1",
            "android/security/keystore/KeyProperties->DIGEST_SHA512:Ljava/lang/String;", "SHA-512",
            "android/security/keystore/KeyProperties->KEY_ALGORITHM_EC:Ljava/lang/String;", "EC");

    private static final Map<String, Integer> BASE64_FLAGS = Map.of(
            "android/util/Base64->DEFAULT:I", 0,
            "android/util/Base64->NO_PADDING:I", 1,
            "android/util/Base64->NO_WRAP:I", 2,
            "android/util/Base64->CRLF:I", 4,
            "android/util/Base64->URL_SAFE:I", 8);

    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass dvmClass, String signature, VaList vaList) {
        switch (signature) {
            // null Context makes JNI_OnLoad skip straight to RegisterNatives instead of calling getApplication().
            case "android/app/ActivityThread->currentActivityThread()Landroid/app/ActivityThread;":
                return null;
            case "java/security/KeyStore->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;":
                return vm.resolveClass("java/security/KeyStore").newObject(keyStoreAliases);
            case "java/security/Signature->getInstance(Ljava/lang/String;)Ljava/security/Signature;": {
                SignatureState state = new SignatureState();
                StringObject algo = vaList.getObjectArg(0);
                state.algorithm = algo == null ? null : algo.getValue();
                return vm.resolveClass("java/security/Signature").newObject(state);
            }
            case "android/util/Base64->decode(Ljava/lang/String;I)[B": {
                StringObject encoded = vaList.getObjectArg(0);
                return new ByteArray(vm, Base64.getDecoder().decode(encoded.getValue()));
            }
            default:
                return super.callStaticObjectMethodV(vm, dvmClass, signature, vaList);
        }
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/security/KeyStore->load(Ljava/security/KeyStore$LoadStoreParameter;)V":
            case "java/security/KeyStore->load(Ljava/io/InputStream;[C)V":
                return;
            case "java/security/Signature->initSign(Ljava/security/PrivateKey;)V": {
                SignatureState state = (SignatureState) dvmObject.getValue();
                DvmObject<?> key = vaList.getObjectArg(0);
                state.signKey = key == null ? null : key.getValue();
                return;
            }
            case "java/security/Signature->initVerify(Ljava/security/PublicKey;)V": {
                SignatureState state = (SignatureState) dvmObject.getValue();
                DvmObject<?> key = vaList.getObjectArg(0);
                state.verifyKey = key == null ? null : key.getValue();
                return;
            }
            case "java/security/Signature->update([B)V": {
                SignatureState state = (SignatureState) dvmObject.getValue();
                byte[] data = argBytes(vaList, 0);
                if (data != null) state.buffer.writeBytes(data);
                return;
            }
            case "java/security/Signature->update([BII)V": {
                SignatureState state = (SignatureState) dvmObject.getValue();
                byte[] data = argBytes(vaList, 0);
                int off = vaList.getIntArg(1);
                int len = vaList.getIntArg(2);
                if (data != null) state.buffer.write(data, off, len);
                return;
            }
            default:
                super.callVoidMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public DvmObject<?> callObjectMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        switch (signature) {
            case "java/security/KeyStore->getKey(Ljava/lang/String;[C)Ljava/security/Key;": {
                StringObject alias = vaList.getObjectArg(0);
                return vm.resolveClass("java/security/PrivateKey").newObject(keyPairFor(alias.getValue()));
            }
            case "java/lang/String->getBytes(Ljava/nio/charset/Charset;)[B": {
                DvmObject<?> charsetObj = vaList.getObjectArg(0);
                java.nio.charset.Charset cs = charsetObj != null && charsetObj.getValue() instanceof java.nio.charset.Charset c
                        ? c : java.nio.charset.StandardCharsets.UTF_8;
                return new ByteArray(vm, ((String) dvmObject.getValue()).getBytes(cs));
            }
            case "java/security/Signature->sign()[B": {
                SignatureState state = (SignatureState) dvmObject.getValue();
                try {
                    Signature s = signatureFor(state.algorithm);
                    s.initSign((PrivateKey) resolveSignKey(state.signKey, state.algorithm));
                    s.update(state.buffer.toByteArray());
                    return new ByteArray(vm, s.sign());
                } catch (Exception e) {
                    throw new IllegalStateException("sign failed (" + state.algorithm + ")", e);
                }
            }
            default:
                return super.callObjectMethodV(vm, dvmObject, signature, vaList);
        }
    }

    @Override
    public boolean callBooleanMethodV(BaseVM vm, DvmObject<?> dvmObject, String signature, VaList vaList) {
        if ("java/security/Signature->verify([B)Z".equals(signature)) {
            SignatureState state = (SignatureState) dvmObject.getValue();
            byte[] sig = argBytes(vaList, 0);
            try {
                Signature s = signatureFor(state.algorithm);
                s.initVerify((PublicKey) resolveVerifyKey(state.verifyKey, state.algorithm));
                s.update(state.buffer.toByteArray());
                return sig != null && s.verify(sig);
            } catch (SignatureException e) {
                // A malformed signature blob is a rejection, not a bridge fault.
                return false;
            } catch (Exception e) {
                throw new IllegalStateException("verify failed (" + state.algorithm + ")", e);
            }
        }
        return super.callBooleanMethodV(vm, dvmObject, signature, vaList);
    }

    @Override
    public DvmObject<?> getStaticObjectField(BaseVM vm, DvmClass dvmClass, String signature) {
        String s = KEY_PROPERTIES_STRINGS.get(signature);
        if (s != null) {
            return new StringObject(vm, s);
        }
        if ("java/nio/charset/StandardCharsets->UTF_8:Ljava/nio/charset/Charset;".equals(signature)) {
            return vm.resolveClass("java/nio/charset/Charset").newObject(java.nio.charset.StandardCharsets.UTF_8);
        }
        return super.getStaticObjectField(vm, dvmClass, signature);
    }

    @Override
    public int getStaticIntField(BaseVM vm, DvmClass dvmClass, String signature) {
        Integer v = BASE64_FLAGS.get(signature);
        return v != null ? v : super.getStaticIntField(vm, dvmClass, signature);
    }
}
