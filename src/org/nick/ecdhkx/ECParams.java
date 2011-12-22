package org.nick.ecdhkx;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.HashMap;
import java.util.Map;

import org.spongycastle.jce.ECPointUtil;
import org.spongycastle.util.encoders.Hex;

class ECParams {

    String name;
    String p;
    String a;
    String b;
    String G;
    String n;
    int h;

    BigInteger pBi;
    ECFieldFp fp;
    EllipticCurve curve;
    BigInteger aBi;
    BigInteger bBi;
    ECPoint ecpG;
    BigInteger nBi;

    ECParams(String name) {
        this.name = name;
    }

    public static final ECParams secp160k1 = new ECParams("secp160k1");
    public static final ECParams secp224k1 = new ECParams("secp224k1");

    private static final Map<String, ECParams> PARAMS = new HashMap<String, ECParams>();

    static {
        secp160k1.p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73";
        secp160k1.a = "0000000000000000000000000000000000000000";
        secp160k1.b = "0000000000000000000000000000000000000007";
        secp160k1.G = "023B4C382CE37AA192A4019E763036F4F5DD4D7EBB";
        secp160k1.n = "0100000000000000000001B8FA16DFAB9ACA16B6B3";
        secp160k1.h = 1;
        secp160k1.init();
        PARAMS.put(secp160k1.name, secp160k1);

        secp224k1.p = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D";
        secp224k1.a = "00000000000000000000000000000000000000000000000000000000";
        secp224k1.b = "00000000000000000000000000000000000000000000000000000005";
        secp224k1.G = "03A1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C";
        secp224k1.n = "010000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7";
        secp224k1.h = 1;
        secp224k1.init();
        PARAMS.put(secp224k1.name, secp224k1);
    }

    static ECParams getParams(String name) {
        return PARAMS.get(name);
    }

    private void init() {
        pBi = new BigInteger(p, 16);
        fp = new ECFieldFp(pBi);
        aBi = new BigInteger(a, 16);
        bBi = new BigInteger(b, 16);

        curve = new EllipticCurve(fp, getA(), bBi);

        ecpG = ECPointUtil.decodePoint(curve, Hex.decode(G));

        nBi = new BigInteger(n, 16);
    }

    BigInteger getP() {
        return pBi;
    }

    BigInteger getA() {
        BigInteger positiveA = pBi.add(aBi);
        boolean useA = aBi.abs().equals(aBi);

        return useA ? aBi : positiveA;
    }

    BigInteger getB() {
        return bBi;
    }

    ECFieldFp getField() {
        return fp;
    }

    ECPoint getG() {
        return ecpG;
    }

    BigInteger getN() {
        return nBi;
    }
}
