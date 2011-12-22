package org.nick.ecdhkx;

import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

import javax.crypto.KeyAgreement;

import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import android.util.Log;

public class Crypto {

    private static final String TAG = Crypto.class.getSimpleName();

    private static final String PROVIDER = "SC";

    private static final String KEGEN_ALG = "ECDH";

    private static Crypto instance;

    static {
        Security.addProvider(new org.spongycastle.jce.provider.BouncyCastleProvider());
    }

    private KeyFactory kf;
    private KeyPairGenerator kpg;

    static synchronized Crypto getInstance() {
        if (instance == null) {
            instance = new Crypto();
        }

        return instance;
    }

    private Crypto() {
        try {
            kf = KeyFactory.getInstance(KEGEN_ALG, PROVIDER);
            kpg = KeyPairGenerator.getInstance(KEGEN_ALG, PROVIDER);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    static void listAlgorithms(String algFilter) {
        Provider[] providers = Security.getProviders();
        for (Provider p : providers) {
            String providerStr = String.format("%s/%s/%f\n", p.getName(),
                    p.getInfo(), p.getVersion());
            Log.d(TAG, providerStr);
            Set<Service> services = p.getServices();
            List<String> algs = new ArrayList<String>();
            for (Service s : services) {
                boolean match = true;
                if (algFilter != null) {
                    match = s.getAlgorithm().toLowerCase()
                            .contains(algFilter.toLowerCase());
                }

                if (match) {
                    String algStr = String.format("\t%s/%s/%s", s.getType(),
                            s.getAlgorithm(), s.getClassName());
                    algs.add(algStr);
                }
            }

            Collections.sort(algs);
            for (String alg : algs) {
                Log.d(TAG, "\t" + alg);
            }
            Log.d(TAG, "");
        }
    }

    static void listCurves() {
        Log.d(TAG, "Supported named curves:");
        Enumeration<?> names = SECNamedCurves.getNames();
        while (names.hasMoreElements()) {
            Log.d(TAG, "\t" + (String) names.nextElement());
        }
    }

    synchronized KeyPair generateKeyPairParams(ECParams ecp) throws Exception {
        EllipticCurve curve = toCurve(ecp);
        ECParameterSpec esSpec = new ECParameterSpec(curve, ecp.getG(),
                ecp.getN(), ecp.h);

        kpg.initialize(esSpec);

        return kpg.generateKeyPair();
    }

    synchronized KeyPair generateKeyPairNamedCurve(String curveName)
            throws Exception {
        ECGenParameterSpec ecParamSpec = new ECGenParameterSpec(curveName);
        kpg.initialize(ecParamSpec);

        return kpg.generateKeyPair();
    }

    static String base64Encode(byte[] b) {
        try {
            return new String(Base64.encode(b), "ASCII");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    static String hex(byte[] bytes) {
        try {
            return new String(Hex.encode(bytes), "ASCII");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] base64Decode(String str) {
        return Base64.decode(str);
    }

    static EllipticCurve toCurve(ECParams ecp) {
        ECFieldFp fp = new ECFieldFp(ecp.getP());

        return new EllipticCurve(fp, ecp.getA(), ecp.getB());
    }

    byte[] ecdh(PrivateKey myPrivKey, PublicKey otherPubKey) throws Exception {
        ECPublicKey ecPubKey = (ECPublicKey) otherPubKey;
        Log.d(TAG, "public key Wx: "
                + ecPubKey.getW().getAffineX().toString(16));
        Log.d(TAG, "public key Wy: "
                + ecPubKey.getW().getAffineY().toString(16));

        KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", PROVIDER);
        keyAgreement.init(myPrivKey);
        keyAgreement.doPhase(otherPubKey, true);

        return keyAgreement.generateSecret();
    }

    synchronized PublicKey readPublicKey(String keyStr) throws Exception {
        X509EncodedKeySpec x509ks = new X509EncodedKeySpec(
                Base64.decode(keyStr));
        return kf.generatePublic(x509ks);
    }

    synchronized PrivateKey readPrivateKey(String keyStr) throws Exception {
        PKCS8EncodedKeySpec p8ks = new PKCS8EncodedKeySpec(
                Base64.decode(keyStr));

        return kf.generatePrivate(p8ks);
    }

    synchronized KeyPair readKeyPair(String pubKeyStr, String privKeyStr)
            throws Exception {
        return new KeyPair(readPublicKey(pubKeyStr), readPrivateKey(privKeyStr));
    }

}
