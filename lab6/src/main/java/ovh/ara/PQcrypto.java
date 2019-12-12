package ovh.ara;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.mceliece.McElieceCipher;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceKeysToParams;
import org.pqcrypto.newhope.NewHope;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PQcrypto {

    private static boolean compare(byte[] a, byte[] b)
    {
        if (a.length != b.length)
            return false;
        for (int i = 0; i < a.length; ++i) {
            if (a[i] != b[i])
                return false;
        }
        return true;
    }

    public PQcrypto(){
        // Generate the private and public keys for Alice.
        NewHope alice = new NewHope();
        NewHope bob = new NewHope();
        byte[] senda = new byte [NewHope.SENDABYTES];
        alice.keygen(senda, 0);

        // Generate the public key and shared secret for Bob.

        byte[] sendb = new byte [NewHope.SENDBBYTES];
        byte[] key_b = new byte [NewHope.SHAREDBYTES];
        bob.sharedb(key_b, 0, sendb, 0, senda, 0);

        // Generate the shared secret for Alice.
        byte[] key_a = new byte [NewHope.SHAREDBYTES];
        alice.shareda(key_a, 0, sendb, 0);

        if (compare(key_a, key_b)) {
            System.out.println("Shared keys do match!");
        }
    }




    public static void main(String args[]) throws Exception{
        PQcrypto a = new PQcrypto();

    }

}
