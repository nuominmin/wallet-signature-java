package com.example;

import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Hash;
import org.web3j.utils.Numeric;
import org.web3j.crypto.Keys;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import com.example.SolSHA3;

public class EthereumSigner {
    public static String signMessage(ECKeyPair privateKey,List<String> types, List<Object> values) throws Exception {
        byte[] message = SolSHA3.SoliditySHA3(types,values);

        String prefix = "\u0019Ethereum Signed Message:\n" + message.length;
        byte[] prefixBytes = prefix.getBytes(StandardCharsets.UTF_8);

        byte[] ethMessage = new byte[prefixBytes.length + message.length];
        System.arraycopy(prefixBytes, 0, ethMessage, 0, prefixBytes.length);
        System.arraycopy(message, 0, ethMessage, prefixBytes.length, message.length);

        byte[] ethHash = Hash.sha3(ethMessage);

        Sign.SignatureData signatureData = Sign.signMessage(ethHash, privateKey, false);

        byte[] r = signatureData.getR();
        byte[] s = signatureData.getS();
        byte[] signatureBytes = new byte[65];
        System.arraycopy(r, 0, signatureBytes, 0, 32);
        System.arraycopy(s, 0, signatureBytes, 32, 32);
        if (signatureData.getV() != null && signatureData.getV().length > 0) {
            signatureBytes[64] = signatureData.getV()[0];
        }

        return Numeric.toHexString(signatureBytes);
    }

    public static void main(String[] args) throws Exception {
        String txHash = "0x10a168b7c1d4a3a716a9198d23cd03e5e9373ebc1cfdb83935d250c287ada190"; // 7522190690464635411539473051680820747099471556785250774231942733071196725648
        BigInteger amt = new BigInteger("2001").multiply(BigInteger.TEN.pow(7));
        String from = "0x0000E3E55554Affb68617C09D9564EeFC28A2222";
        String to = "0xFdcF1Be325F7036Ca9125faa96efb539757B03b6";
        String tick = "0x65746869";
        String privateKeyHex = "3d109b6278b31c67994c0c1b8b75f3e75ed39f156795e5e68baf839188bc1dc7";

        BigInteger privateKey = new BigInteger(privateKeyHex, 16);
        ECKeyPair ecKeyPair = ECKeyPair.create(privateKey);


        List<String> types = Arrays.asList("bytes32", "uint256", "address", "address", "bytes4");
        List<Object> values = new ArrayList<>();
        values.add(txHash);
        values.add(amt);
        values.add(from);
        values.add(to);
        values.add(tick);

        String sign = EthereumSigner.signMessage(ecKeyPair, types, values);

        String address = "0x" + Keys.getAddress(ecKeyPair.getPublicKey());

        System.out.println("privateKey: " + privateKeyHex);
        System.out.println("publicKey: " + address);
        System.out.println("txHash: " + txHash);
        // System.out.println("dataTypes: " + Arrays.toString(dataTypes));
        System.out.println("amt: " + amt.toString());
        System.out.println("from: " + from);
        System.out.println("to: " + to);
        System.out.println("tick: " + tick);
        System.out.println("sign: " + sign);
        System.out.println("eq: " + sign.equals("0x1e6a4ba761f3043593e564bfd3fa63bf529b6a908eb5afb30070cda03d1da27c1a8d73a0a2e1931e27fb7446c12fbe1167f8e90284ab0972dc54b812ea2f597f1b"));
    }
}
