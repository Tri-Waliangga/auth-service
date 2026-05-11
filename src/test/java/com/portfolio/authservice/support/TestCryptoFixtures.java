package com.portfolio.authservice.support;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class TestCryptoFixtures {

    public static final String CLIENT_ID = "client-id";
    public static final String TIMESTAMP = "2026-05-07T15:00:00+07:00";
    public static final String AUTH_STRING_TO_SIGN = CLIENT_ID + "|" + TIMESTAMP;

    public static final String AUTH_SIGNATURE =
            "ppgb/XrGGAt2IoMO8AiQGFfsquzBMvWvq0NpV/8+ofYGkP5FLtRokEpKG4Ep38TVQROvgNYj/9HMw8nbbihN2E/DOoZ5A+BnZKbns2Di4N0PH54hkKF0hkN7qtntKCJipRINPZ0QrratHcSI8Z/ENkdAACnuBBjAO0PDMCNT357hYvBoJAfSOyH8NEw2JXNpIB4Isi2hlnos+GYy80OhO+3rqf0UQYZTruixV41TbLCkGHkajb1LaxqntM2wuZMXfBWwGVz7bIgAYLJpcFxgZu5ZYnHM8R0reyiwrX91ChVvmhb4q0uwtaJGYRzHt643uw5wzOHQUseT2k26Q8TH1g==";
    public static final String EXPLICIT_STRING_TO_SIGN = "custom-string-to-sign";
    public static final String EXPLICIT_SIGNATURE =
            "eZNkJH+QVuWmQfBoQluyEfXH8mXn2fRkQpUKnADEzwelm+ZM7VByYZYbe/7m+31dpZ98Ji95jHvh2KiBBxz5xio1YLRtSXzUVHYyFPvHwNwX3Vqi39yFR0fBm5Iawr1OoZnRh3excM65e2hYd8NVYdm4SBDlJqPdrOI26nuC9aXCNGSupb8XlraKLQBsByfF9PkjZsAUOB/04I8tA5RM8ErHyrX4f9zXFrFH4ocnlIO2KcKuXQ2qfJXLEzup2vu1kjufbG8FARgAbjs1OTYKCide/Fb57DsPKpstI4u5/potDCR1buWhelK2OVdHRZGueGHX8958OfJRm/p90BWtFQ==";
    public static final String OTHER_KEY_AUTH_SIGNATURE =
            "HvCAH2YzsZn5cScCTE+6GBwitcamAFCFkL21XaV4BZyR/ODirqhp0dmWXIn5pQ14T4jHoyNrkYYuAp5trGZUNOyWZe3WKQ7ou4R5gmGDEQ5bvmnMqoxCo0wmAt4TEHGnfP8Zcja9aIf0GTasinOSEG6G4bqvsYE1PbUh08tJS9OaLbpHcc0WtEF/60QASkp/BMVLvNW+2Cb4sk0nZYtWA98GgP3Pm987cJ+C0b2ubR3k7Jsfk6GmamWcctxKf/4WizklbMWCzmg/5Fys5+HBY5Aun4tpjyHzGySNJXmHvA5x8cIoZpJ4u81/BDO8FTdA8k9wZPP3p9w27/OhXlbRTg==";

    public static final String PRIVATE_KEY_PEM = """
            -----BEGIN PRIVATE KEY-----
            MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC81/yA1DXSA+EJ
            Obkg7KJIVN51yA1mJ3qDEh39AMRWhnXmUyculHa5ATkozwfMI+nB2cy7T54M4ntc
            UiOJUYowQj+BWucWD2szuM8TTEjHgoK03IgbqqU0KHnkTHRVQkGFxlv3Ujqx0HQC
            +KkMc4q6ENQ0smwHolUuZth/Vf1fo+y3TpexrM8aH4dFh0+4IwA4gvqslSmCwZOJ
            PjUaMVUAd17DAlXvxddU2+RUzDsMJUycGIIKiddrvaqQePXMO9xMLyMiQyerA/K7
            ttSuKs2x1I+TOSxJfYAVKGTBFGIcl1eevRWF8QWtHsnYK03HBHjTs7x/ATTfTGcN
            s6G40u8bAgMBAAECggEAE0+rq3RIAVnSiDzQu4GyAgnlFTqnyB5ZubqUuiZ7GCAN
            lsftFfx/puFC+kiFkxt0ZZWYs+pAjtpq5At679QYo2EQQ8b1zPyMVBCI4yp7YiTs
            qdhyy2V9bw0ukyk7AkGmwqqAsBTGxMqSJSr5hTjxjZ/NRjWdX4B7C9DfldHyJEv0
            IDknzhkvQCEpeswapGHGGwfFYLIhqgfRg93rYrAE+FO2RIuhwqVM+rYWNbCeeydd
            gRoJBXEy7tbbV848DivRrtT3IjK5UHj/8XQrVXomdHKmj9i8xYVnzn+lYrOb7bik
            K+OEp857oDE39BHeaND+ORkf+Mb6K26C+kC6nPv9aQKBgQDvhnJT5koq287Rm1T5
            2wPPX47IztErKKm8bCwOn95AqS55JiI+CwrYZa1w3Qp+iv9L1I2/IOYWpXKITUl2
            Pg2VORLt9iysB4oL5C47Zqhe16JAtNhlNE+2qjDNAhNmtyIYOO0/Qzq/7EwWVCXz
            cjNdDqj1EOAjo4hbMVadBtVwaQKBgQDJ1SQ0SfZ7XytY6f9mZ3yEP6fAF+Jfgo8J
            dv/BI7Tpm+ummDMrdajcCHxFUd7TB/t4JqrjUy+61vF+fIzkff7qxMDGSDa3NT+v
            HlLn+BHowLOLxRkp57WiNFHUEuAOabVFvm53n8cBiWcpF6iWrYldIvcd6lPCPhBD
            HhhXsUXy4wKBgDh8LTPp5+2pfmFhzy1I3+Ikd8iVNTCHW1fK7qzYOJJpE0OQoZye
            AAW+HKO0DMiAwOnCC1daS8hlZdgM2dkfkxZwqi0h07ER6hUZz2lEsUoEcgfuXeWn
            63B5PB7scWTUpR6vNguoMA+YiuztFTIO6Vv1nBSG0US2SO6weOt49BaZAoGAOiQj
            NMjlry6ALzHhN9+x1+r6aPS4amkSyVg1Xq7pi6412RzZCLjxNsle+x0Vglc3UqpY
            6flps3n9wUEh2SSOjZS2L6hX0rkNKmYi3d3xUspILohNsmukQCCwPdZeIujCpl+w
            NNebHU82n3jIQPemrWTIKR76l+cHCj6eJozTqJ8CgYBGiwTKen/8OorkkvbFcTpf
            QS/xIQKVqQ/OyMv+y9pkIwlvykE/ewxUXjEkRymCOW9/8FsICiXKPCMNo65vS7OD
            i/7iMdrgzCBY8NuIJ1DRpikVOQiwUAbFWzCKKWChJzNPcaqNlnu1QK07lAd4KTjm
            i2JVE+bosSC1q91E5M343Q==
            -----END PRIVATE KEY-----
            """;

    public static final String PUBLIC_KEY_PEM = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvNf8gNQ10gPhCTm5IOyi
            SFTedcgNZid6gxId/QDEVoZ15lMnLpR2uQE5KM8HzCPpwdnMu0+eDOJ7XFIjiVGK
            MEI/gVrnFg9rM7jPE0xIx4KCtNyIG6qlNCh55Ex0VUJBhcZb91I6sdB0AvipDHOK
            uhDUNLJsB6JVLmbYf1X9X6Pst06XsazPGh+HRYdPuCMAOIL6rJUpgsGTiT41GjFV
            AHdewwJV78XXVNvkVMw7DCVMnBiCConXa72qkHj1zDvcTC8jIkMnqwPyu7bUrirN
            sdSPkzksSX2AFShkwRRiHJdXnr0VhfEFrR7J2CtNxwR407O8fwE030xnDbOhuNLv
            GwIDAQAB
            -----END PUBLIC KEY-----
            """;

    public static final String OTHER_PUBLIC_KEY_PEM = """
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp+qIPMV/391eq1Zh2zyi
            OZP4so7nSwRPo4YwhOX1lN0lsw7jf+kCQP0yljGcnjtNtbKkXEnM+UBm9cVNGCpm
            jntsMjKtwBz4oQycasjh9CsWKE5VKczW5zQjKucVqH1t1Wu1n+iiGTyPJ8qilq8B
            HxhCrM4Hsb4et/i6ElKlUqbMpY7nqs+f0JUe3G+cs5Wf2fWoQCjEAuajbEc9vohg
            4i1BBpsXOOQtR7oGBW25jqC+fKPAv+DhFcNRz9wp+qRIO45sVBSQVFIf/Qte1lOM
            FpaY6jeQYHG7qHSw+2+iejaBYmRvY9/a0o+UpRc7GAx1XCWTALtqr9ShefqCfwpm
            kwIDAQAB
            -----END PUBLIC KEY-----
            """;

    private TestCryptoFixtures() {
    }

    public static String escapedPrivateKeyPem() {
        return PRIVATE_KEY_PEM.replace("\n", "\\n");
    }

    public static String escapedPublicKeyPem() {
        return PUBLIC_KEY_PEM.replace("\n", "\\n");
    }

    public static RSAPrivateKey privateKey() throws GeneralSecurityException {
        byte[] keyBytes = Base64.getDecoder().decode(stripPem(PRIVATE_KEY_PEM, "PRIVATE KEY"));
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    public static RSAPublicKey publicKey() throws GeneralSecurityException {
        byte[] keyBytes = Base64.getDecoder().decode(stripPem(PUBLIC_KEY_PEM, "PUBLIC KEY"));
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    public static String sign(String value) throws GeneralSecurityException {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey());
        signer.update(value.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    private static String stripPem(String pem, String type) {
        return pem
                .replace("-----BEGIN " + type + "-----", "")
                .replace("-----END " + type + "-----", "")
                .replaceAll("\\s", "");
    }
}
