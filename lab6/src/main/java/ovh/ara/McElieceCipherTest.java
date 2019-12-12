package ovh.ara;

import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mceliece.*;

public class McElieceCipherTest {
    SecureRandom keyRandom = new SecureRandom();
    String message;
    byte messageBytes[];
    public McElieceCipherTest(){this("this is a message");}
    public McElieceCipherTest(String message){
        this.message = message;
        this.messageBytes = message.getBytes();
    }


    public void performTest() throws InvalidCipherTextException {

        System.out.println("Encoding a message \n" + message);
        McElieceParameters params = new McElieceParameters();
        McElieceKeyPairGenerator mcElieceKeyGen = new McElieceKeyPairGenerator();
        McElieceKeyGenerationParameters genParam = new McElieceKeyGenerationParameters(keyRandom, params);

        mcElieceKeyGen.init(genParam);
        AsymmetricCipherKeyPair pair = mcElieceKeyGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPublic(), keyRandom);
        McElieceCipher mcEliecePKCSDigestCipher = new McElieceCipher();
        System.out.println("Generated Key Pair");

        // initialize for encryption
        mcEliecePKCSDigestCipher.init(true, param);

        // encrypt
        byte[] enc = mcEliecePKCSDigestCipher.messageEncrypt(messageBytes);

        // initialize for decryption
        mcEliecePKCSDigestCipher.init(false, pair.getPrivate());
        McEliecePrivateKeyParameters x = (McEliecePrivateKeyParameters)(pair.getPrivate());
        System.out.println("Length: " + x.getN() + " <-> Dimension: " + x.getK());
        byte[] constructedmessage = mcEliecePKCSDigestCipher.messageDecrypt(enc);

        String decoded = new String(constructedmessage);
        if (!decoded.equals(message)) {
            throw new InvalidCipherTextException("en/decryption fails");
        } else {
            System.out.println("Success!\nDecoded message:");
            System.out.println(new String(constructedmessage));
        }


    }

    public static void main(String[] args) throws Exception {
        new McElieceCipherTest().performTest();
    }

}
