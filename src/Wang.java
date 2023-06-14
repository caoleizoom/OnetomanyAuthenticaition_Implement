import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Properties;
import java.util.stream.IntStream;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;

public class Wang {
    public static void setup(String pairingParametersFileName, String pkFileName, String mskFileName){
        //generate the system master private key and public key
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g = bp.getG1().newRandomElement().getImmutable();
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element K_pub = g.powZn(s).getImmutable();

        //keep the master private key secret
        Properties mskProp = loadPropFromFile(mskFileName);
        mskProp.setProperty("s",Base64.getEncoder().withoutPadding().encodeToString(s.toBytes()));
        storePropToFile(mskProp,mskFileName);

        //public system parameters
        Properties pkProp = new Properties();
        pkProp.setProperty("g",Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        pkProp.setProperty("K_pub",Base64.getEncoder().withoutPadding().encodeToString(K_pub.toBytes()));
        storePropToFile(pkProp,pkFileName);
    }

    public static void userRegistration(String pairingParametersFileName, String pkFileName, String mskFileName, String skFileName, String RID) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties mskProp = loadPropFromFile(mskFileName);
        String sString = mskProp.getProperty("s");
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sString)).getImmutable();

        Properties pkProp = loadPropFromFile(pkFileName);
        String gString = pkProp.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        String K_pubString = pkProp.getProperty("K_pub");
        Element K_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(K_pubString)).getImmutable();

        Element pseudonym = bp.getZr().newRandomElement().getImmutable();
        String expiryTime = String.valueOf(LocalDate.now().plus(1, ChronoUnit.YEARS));
        String pid = pseudonym.toString()+" "+expiryTime;

        Element PK = bp.getG1().newElementFromHash(sha1(pid),0,sha1(pid).length).getImmutable();
        Element SK = PK.powZn(s).getImmutable();

        pkProp.setProperty("PK"+RID,Base64.getEncoder().withoutPadding().encodeToString(PK.toBytes()));
        storePropToFile(pkProp,pkFileName);

        Properties skProp = loadPropFromFile(skFileName);
        skProp.setProperty("SK"+RID,Base64.getEncoder().withoutPadding().encodeToString(SK.toBytes()));
        skProp.setProperty("pid"+RID,pid);
        storePropToFile(skProp,skFileName);
    }

    public static void msgGen(String pairingParametersFileName, String pkFileName, String skFileName, String msgFileName, String ID){
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFileName);
        String PString = pkProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PString)).getImmutable();
        String P_pubString = pkProp.getProperty("P_pub");
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubString)).getImmutable();

        Properties skProp = loadPropFromFile(skFileName);
        String RString = skProp.getProperty("R"+ID);
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RString)).getImmutable();

        Element a = bp.getZr().newRandomElement().getImmutable();
        skProp.setProperty("a"+ID,Base64.getEncoder().withoutPadding().encodeToString(a.toBytes()));
        storePropToFile(skProp,skFileName);

        Element T1 = R.powZn(a).getImmutable();
        Element T2 = P_pub.powZn(a).getImmutable();

        Properties msgProp = loadPropFromFile(msgFileName);
        msgProp.setProperty("R"+ID,Base64.getEncoder().withoutPadding().encodeToString(R.toBytes()));
        msgProp.setProperty("T1"+ID,Base64.getEncoder().withoutPadding().encodeToString(T1.toBytes()));
        msgProp.setProperty("T2"+ID,Base64.getEncoder().withoutPadding().encodeToString(T2.toBytes()));
        storePropToFile(msgProp,msgFileName);
    }

    public  static void sessionKeyGen(String pairingParametersFileName, String pkFileName, String skFileName, String msgFileName, String sender, String receiver) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFileName);
        String PString = pkProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PString)).getImmutable();
        String P_pubString = pkProp.getProperty("P_pub");
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubString)).getImmutable();

        Properties skProp = loadPropFromFile(skFileName);
        String siString = skProp.getProperty("s"+receiver);
        Element si = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(siString)).getImmutable();
        String aString = skProp.getProperty("a"+receiver);
        Element a = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(aString)).getImmutable();

        Properties msgProp = loadPropFromFile(msgFileName);
        String T1_s_String =msgProp.getProperty("T1"+sender);
        Element T1_s = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T1_s_String)).getImmutable();
        String T2_s_String = msgProp.getProperty("T2"+sender);
        Element T2_s = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T2_s_String)).getImmutable();
        String RString = msgProp.getProperty("R"+sender);
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RString)).getImmutable();

        String T1_r_String = msgProp.getProperty("T1"+receiver);
        Element T1_r = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T1_r_String)).getImmutable();
        String T2_r_String = msgProp.getProperty("T2"+receiver);
        Element T2_r = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(T2_r_String)).getImmutable();

        Element K = T1_s.add(T2_s.powZn(bp.getZr().newElementFromHash(sha1(sender+R.toString()),0,sha1(sender+R.toString()).length))).powZn(a.mul(si));
        byte [] H2 ;
        if(receiver == "Bob"){
            H2 = sha1(sender+receiver+T1_s.toString()+T2_s.toString()+T1_r.toString()+T2_r.toString()+K.toString());
        } else {
            H2 = sha1(receiver+sender+T1_r.toString()+T2_r.toString()+T1_s.toString()+T2_s.toString()+K.toString());
        }

        Element sk = bp.getZr().newElementFromHash(H2,0,H2.length);
        skProp.setProperty("sk"+receiver,Base64.getEncoder().withoutPadding().encodeToString(sk.toBytes()));
        storePropToFile(skProp,skFileName);
    }
    public static void keyAgreeement(String pairingParametersFileName, String pkFile, String skFile, String msgFile, String vehicle1, String vehicle2) throws NoSuchAlgorithmException {
        msgGen(pairingParametersFileName,pkFile,skFile,msgFile,vehicle1);
        msgGen(pairingParametersFileName,pkFile,skFile,msgFile,vehicle2);
        sessionKeyGen(pairingParametersFileName,pkFile,skFile,msgFile,vehicle1,vehicle2);
        sessionKeyGen(pairingParametersFileName,pkFile,skFile,msgFile,vehicle2,vehicle1);
    }


    public static void storePropToFile(Properties prop, String fileName){
        try(FileOutputStream out = new FileOutputStream(fileName)){
            prop.store(out, null);
        }
        catch (IOException e) {
            e.printStackTrace();
            System.out.println(fileName + " save failed!");
            System.exit(-1);
        }
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();
        try (FileInputStream in = new FileInputStream(fileName)){
            prop.load(in);
        }
        catch (IOException e){
            e.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }
        return prop;
    }

    //单向散列函数
    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        String pairingParametersFileName = "./a.properties";
        String dir = "./data/Wang_data/";
        String pkFile = dir + "pk.properties";
        String mskFile = dir + "msk.properties";
        String skFile = dir + "sk.properties";
        String msgFile = dir + "msg.properties";
        String IDi = "Alice";
        String IDj = "Bob";
        //setup(pairingParametersFileName,pkFile,mskFile);
        userRegistration(pairingParametersFileName,pkFile,mskFile,skFile,IDi);

    }

}
