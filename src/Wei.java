import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Properties;


public class Wei {
    public static void setup(String pairingParametersFileName, String pkFileName, String mskFileName){
        //generate the system master private key and public key
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element P_pub = P.powZn(s).getImmutable();

        //keep the master private key secret
        Properties mskProp = loadPropFromFile(mskFileName);
        mskProp.setProperty("s",Base64.getEncoder().withoutPadding().encodeToString(s.toBytes()));
        storePropToFile(mskProp,mskFileName);

        //public system parameters
        Properties pkProp = new Properties();
        pkProp.setProperty("P",Base64.getEncoder().withoutPadding().encodeToString(P.toBytes()));
        pkProp.setProperty("P_pub",Base64.getEncoder().withoutPadding().encodeToString(P_pub.toBytes()));
        storePropToFile(pkProp,pkFileName);
    }

    public static void vehicleRegistration(String pairingParametersFileName, String pkFileName, String mskFileName, String vskFileName, Element RID) throws NoSuchAlgorithmException, IOException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties mskProp = loadPropFromFile(mskFileName);
        String sString = mskProp.getProperty("s");
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sString)).getImmutable();

        Properties pkProp = loadPropFromFile(pkFileName);
        String PString = pkProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PString)).getImmutable();
        String K_pubString = pkProp.getProperty("P_pub");
        Element K_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(K_pubString)).getImmutable();


        Element l = bp.getZr().newElementFromHash(sha1(s.toString()+RID),0,sha1(s.toString()+RID).length);

        Properties vskProp = loadPropFromFile(vskFileName);
        vskProp.setProperty("l"+RID,Base64.getEncoder().withoutPadding().encodeToString(l.toBytes()));
        storePropToFile(vskProp,vskFileName);
    }
    public static void rsuRegistration(String pairingParametersFileName, String pkFileName, String mskFileName, String rskFileName, Element IDj) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties mskProp = loadPropFromFile(mskFileName);
        String sString = mskProp.getProperty("s");
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sString)).getImmutable();

        Properties pkProp = loadPropFromFile(pkFileName);
        String PString = pkProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PString)).getImmutable();

        Element d = bp.getZr().newRandomElement().getImmutable();

        Element Qj = P.powZn(d).getImmutable();

        pkProp.setProperty("Qj",Base64.getEncoder().withoutPadding().encodeToString(Qj.toBytes()));
        storePropToFile(pkProp,pkFileName);



        Element lj = bp.getZr().newElementFromHash(sha1(s.toString()+IDj.toString()),0,sha1(s.toString()+IDj.toString()).length);

        Properties rskProp = loadPropFromFile(rskFileName);
        rskProp.setProperty("IDj", Base64.getEncoder().withoutPadding().encodeToString(IDj.toBytes()));
        rskProp.setProperty("lj",Base64.getEncoder().withoutPadding().encodeToString(lj.toBytes()));
        storePropToFile(rskProp,rskFileName);
    }

    public static void threePartyAuthentication1(String pairingParametersFileName, String pkFileName, Element RID ,String vskFileName, String msgFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFileName);
        String PString = pkProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PString)).getImmutable();
        String P_pubString = pkProp.getProperty("P_pub");
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubString)).getImmutable();

        Element r = bp.getZr().newRandomElement().getImmutable();
        String T = String.valueOf(System.currentTimeMillis());
        Element R = P.powZn(r).getImmutable();

        byte[] RIDByte = RID.toBytes();
        byte[] h2 = sha1(P_pub.powZn(r).toString()+T);
        byte[] PID = new byte[h2.length];
        for (int i = 0; i < RIDByte.length; i++){
            PID[i] = (byte)(RIDByte[i] ^ h2[i]);
        }
        Element PIDi = bp.getZr().newElementFromBytes(PID);
        Element k = bp.getZr().newRandomElement().getImmutable();
        Element K = P.powZn(k).getImmutable();
        Properties vskProp = loadPropFromFile(vskFileName);
        String lString = vskProp.getProperty("l"+RID);
        Element l = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(lString)).getImmutable();
        byte[] h3 = sha1(RID.toString()+T+R.toString()+K.toString()+l.toString());
        Element alpha = bp.getZr().newElementFromHash(h3,0, h3.length);

        Properties msgProp = loadPropFromFile(msgFileName);
        msgProp.setProperty("PIDi",Base64.getEncoder().withoutPadding().encodeToString(PIDi.toBytes()));
        msgProp.setProperty("Ti",T);
        msgProp.setProperty("Ri",Base64.getEncoder().withoutPadding().encodeToString(R.toBytes()));
        msgProp.setProperty("Ki",Base64.getEncoder().withoutPadding().encodeToString(K.toBytes()));
        msgProp.setProperty("alpha_i",Base64.getEncoder().withoutPadding().encodeToString(alpha.toBytes()));
        storePropToFile(msgProp,msgFileName);
    }

    public static void threePartyAuthentication2(String pairingParametersFileName, String pkFileName, String rskFileName, String msgFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFileName);
        String PString = pkProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PString)).getImmutable();
        String P_pubString = pkProp.getProperty("P_pub");
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubString)).getImmutable();

        Properties rskProp = loadPropFromFile(rskFileName);
        String IDjString = rskProp.getProperty("IDj");
        Element IDj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(IDjString)).getImmutable();
        String ljString = rskProp.getProperty("lj");
        Element lj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ljString)).getImmutable();
        String T = String.valueOf(System.currentTimeMillis());

        Properties msgProp = loadPropFromFile(msgFileName);
        String alpha_iStrring = msgProp.getProperty("alpha_i");
        Element alpha_i = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(alpha_iStrring)).getImmutable();

        byte[] h4 = sha1(IDj.toString()+T+alpha_i.toString()+lj.toString());
        Element gamma = bp.getZr().newElementFromHash(h4,0, h4.length).getImmutable();



        msgProp.setProperty("IDj",Base64.getEncoder().withoutPadding().encodeToString(IDj.toBytes()));
        msgProp.setProperty("Tj",T);
        msgProp.setProperty("gammaj",Base64.getEncoder().withoutPadding().encodeToString(gamma.toBytes()));
        storePropToFile(msgProp,msgFileName);
    }

    public static void threePartyAuthentication3(String pairingParametersFileName, String pkFileName, String mskFileName, String msgFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFileName);
        String PString = pkProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PString)).getImmutable();
        String P_pubString = pkProp.getProperty("P_pub");
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(P_pubString)).getImmutable();
        String QjString = pkProp.getProperty("Qj");
        Element Qj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QjString)).getImmutable();

        Properties mskProp = loadPropFromFile(mskFileName);
        String sString = mskProp.getProperty("s");
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sString)).getImmutable();


        Properties msgProp = loadPropFromFile(msgFileName);
        String IDjString = msgProp.getProperty("IDj");
        Element IDj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(IDjString)).getImmutable();
        String Tj = msgProp.getProperty("Tj");
        String gammaString = msgProp.getProperty("gammaj");
        Element gammaj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(gammaString)).getImmutable();
        String PIDiString = msgProp.getProperty("PIDi");
        Element PIDi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(PIDiString)).getImmutable();
        String Ti = msgProp.getProperty("Ti");
        String alphaString = msgProp.getProperty("alpha_i");
        Element alphai = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(alphaString)).getImmutable();
        String KString = msgProp.getProperty("Ki");
        Element Ki = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(KString)).getImmutable();
        String RString = msgProp.getProperty("Ri");
        Element Ri = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RString)).getImmutable();


        Element lj = bp.getZr().newElementFromHash(sha1(s.toString()+IDj.toString()),0,sha1(s.toString()+IDj.toString()).length);
        byte[] h4 = sha1(IDj.toString()+Tj+alphai.toString()+lj.toString());
        Element gammaj_ = bp.getZr().newElementFromHash(h4,0, h4.length).getImmutable();


        if (!gammaj_.isEqual(gammaj)){
            return;
        }

        byte[] h2 = sha1(Ri.powZn(s).toString()+Ti);
        byte[] PID = PIDi.toBytes();
        byte[] RID_Byte = new byte[PID.length];

        for (int i = 0; i < PID.length; i++){
            RID_Byte[i] = (byte)(PID[i] ^ h2[i]);
        }

        Element RID_ = bp.getZr().newElementFromBytes(RID_Byte).getImmutable();

        Element li = bp.getZr().newElementFromHash(sha1(s.toString()+RID_.toString()),0,sha1(s.toString()+RID_.toString()).length).getImmutable();
        byte[] h3 = sha1(RID_.toString()+Ti+Ri.toString()+Ki.toString()+li.toString());
        Element alphai_ = bp.getZr().newElementFromHash(h3,0,h3.length).getImmutable();

        if (!alphai.isEqual(alphai_)){
            return;
        }

        String T_TA = String.valueOf(System.currentTimeMillis());
        Element delta_TA = bp.getZr().newElementFromHash(sha1(T_TA+IDj.toString()+Qj.toString()+li.toString()),0,sha1(T_TA+IDj.toString()+Qj.toString()+li.toString()).length);
        Element qeta_TA = bp.getZr().newElementFromHash(sha1(T_TA+PIDi.toString()+alphai.toString()+Ki.toString()+lj.toString()),0,sha1(T_TA+PIDi.toString()+alphai.toString()+Ki.toString()+lj.toString()).length);

        msgProp.setProperty("T_TA",T_TA);
        msgProp.setProperty("delta", Base64.getEncoder().withoutPadding().encodeToString(delta_TA.toBytes()));
        msgProp.setProperty("qeta", Base64.getEncoder().withoutPadding().encodeToString(qeta_TA.toBytes()));
        storePropToFile(msgProp,msgFileName);
    }

    public static void threePartyAuthentication4(String pairingParametersFileName, String pkFileName, String rskFileName, String msgFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties msgProp = loadPropFromFile(msgFileName);
        String PIDiString = msgProp.getProperty("PIDi");
        Element PIDi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(PIDiString)).getImmutable();
        String T_TA = msgProp.getProperty("T_TA");
        String alphaString = msgProp.getProperty("alpha_i");
        Element alphai = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(alphaString)).getImmutable();
        String qetaString = msgProp.getProperty("qeta");
        Element qeta = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(qetaString)).getImmutable();
        String KiString = msgProp.getProperty("Ki");
        Element Ki = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(KiString)).getImmutable();


        Properties rskProp = loadPropFromFile(rskFileName);
        String ljString = rskProp.getProperty("lj");
        Element lj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ljString)).getImmutable();

        Element qeta_ = bp.getZr().newElementFromHash(sha1(T_TA+PIDi.toString()+alphai.toString()+Ki.toString()+lj.toString()),0,sha1(T_TA+PIDi.toString()+alphai.toString()+lj.toString()).length);

        if (!qeta_.isEqual(qeta)){
            return;
        }
    }

    public static void threePartyAuthentication5(String pairingParametersFileName, String pkFileName, String vskFileName,String msgFileName,Element RID) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties msgProp = loadPropFromFile(msgFileName);
        String IDjString = msgProp.getProperty("IDj");
        Element IDj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(IDjString)).getImmutable();
        String deltaString = msgProp.getProperty("delta");
        Element delta = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(deltaString)).getImmutable();
        String T_TA = msgProp.getProperty("T_TA");

        Properties pkProp = loadPropFromFile(pkFileName);
        String QjString = pkProp.getProperty("Qj");
        Element Qj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QjString)).getImmutable();

        Properties vskProp = loadPropFromFile(vskFileName);
        String liString = vskProp.getProperty("l"+RID);
        Element li = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(liString)).getImmutable();

        Element delta_ = bp.getZr().newElementFromHash(sha1(T_TA+IDj.toString()+Qj.toString()+li.toString()),0,sha1(T_TA+IDj.toString()+Qj.toString()+li.toString()).length);

        if (!delta_.isEqual(delta)){
            System.out.println("Fail2!");
            return;
        }

    }

    public static void sessionKeyInit(String pairingParametersFileName, String pkFileName, Element IDj, String groupFileName){
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFileName);
        String PString = pkProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PString)).getImmutable();
        Element kj = bp.getZr().newRandomElement().getImmutable();
        Element Kj = P.powZn(kj).getImmutable();
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

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        String pairingParametersFileName = "./a.properties";
        String dir = "./data/Wei_data/";
        String pkFile = dir + "pk.properties";
        String mskFile = dir + "msk.properties";
        String vskFile = dir + "vsk.properties";
        String rskFile = dir + "rsk.properties";
        String msgFile = dir + "msg.properties";
        String groupFile = dir + "group.properties";

        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element Vi = bp.getZr().newRandomElement().getImmutable();
        System.out.println(Vi);
        Element IDj = bp.getZr().newRandomElement().getImmutable();
        System.out.println(IDj);
        setup(pairingParametersFileName,pkFile,mskFile);
        vehicleRegistration(pairingParametersFileName,pkFile,mskFile,vskFile,Vi);
        rsuRegistration(pairingParametersFileName,pkFile,mskFile,rskFile,IDj);
        for (int i = 0; i < 10; i++) {
            long start = System.currentTimeMillis();
            threePartyAuthentication1(pairingParametersFileName,pkFile,Vi,vskFile,msgFile);
            threePartyAuthentication2(pairingParametersFileName,pkFile,rskFile,msgFile);
            threePartyAuthentication3(pairingParametersFileName,pkFile,mskFile,msgFile);
            threePartyAuthentication4(pairingParametersFileName,pkFile,rskFile,msgFile);
            threePartyAuthentication5(pairingParametersFileName,pkFile,vskFile,msgFile,Vi);
            sessionKeyInit(pairingParametersFileName,pkFile,IDj,groupFile);
            long end = System.currentTimeMillis();
            System.out.println(end-start);
            }
    }
}
