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



public class Das {
    public static void setup(String pairingParametersFileName, String pkFileName, String mskFileName) {
        //generate the system master private key and public key
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element P = bp.getG1().newRandomElement().getImmutable();
        Element x_CA = bp.getZr().newRandomElement().getImmutable();
        Element Q_CA = P.powZn(x_CA).getImmutable();

        //keep the master private key secret
        Properties mskProp = new Properties();
        mskProp.setProperty("x_CA",Base64.getEncoder().withoutPadding().encodeToString(x_CA.toBytes()));
        storePropToFile(mskProp,mskFileName);

        //public system parameters
        Properties pkProp = new Properties();
        pkProp.setProperty("P",Base64.getEncoder().withoutPadding().encodeToString(P.toBytes()));
        pkProp.setProperty("Q_CA",Base64.getEncoder().withoutPadding().encodeToString(Q_CA.toBytes()));
        storePropToFile(pkProp,pkFileName);
    }

    public static void deviceRegistration(String pairingParametersFileName, String pkFileName, String mskFileName, String skFileName, String device) throws NoSuchAlgorithmException {
        //obtain system parameters
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFileName);
        String PString = pkProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PString)).getImmutable();

        //the generation of device's private key and public key
        Properties mskProp = loadPropFromFile(mskFileName);
        String xCaString = mskProp.getProperty("x_CA");
        Element x_CA = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xCaString)).getImmutable();
        Element ID = bp.getZr().newRandomElement().getImmutable();
        Element x = bp.getZr().newRandomElement().getImmutable();
        Element Q = P.powZn(x).getImmutable();
        Element l = bp.getZr().newRandomElement().getImmutable();
        Element A = P.powZn(x.add(l)).getImmutable();
        byte[] H = sha1(ID.toString()+A.toString());
        Element c = x_CA.add(bp.getZr().newElementFromHash(H,0, H.length).mul(x.add(l)));

        //publish the public key
        pkProp.setProperty("Q"+device,Base64.getEncoder().withoutPadding().encodeToString(Q.toBytes()));
        storePropToFile(pkProp,pkFileName);

        //save the private key
        Properties skProp = loadPropFromFile(skFileName);
        skProp.setProperty("ID"+device,Base64.getEncoder().withoutPadding().encodeToString(ID.toBytes()));
        skProp.setProperty("x"+device,Base64.getEncoder().withoutPadding().encodeToString(x.toBytes()));
        skProp.setProperty("A"+device,Base64.getEncoder().withoutPadding().encodeToString(A.toBytes()));
        skProp.setProperty("c"+device,Base64.getEncoder().withoutPadding().encodeToString(c.toBytes()));
        storePropToFile(skProp,skFileName);
    }

    public static void access1(String pairingParametersFileName, String pkFileName, String skFileName, String msgFileName, String device) throws NoSuchAlgorithmException {
        /*
        step1.Di->Dj:MSG1={IDi,Ai,ci,Ti,zi,Ri,Qi}
         */

        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFileName);
        String PString = pkProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PString)).getImmutable();
        String QString = pkProp.getProperty("Q"+device);
        Element Q = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QString)).getImmutable();

        Properties skProp = loadPropFromFile(skFileName);
        String IDString = skProp.getProperty("ID"+device);
        Element ID = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(IDString)).getImmutable();
        String AString = skProp.getProperty("A"+device);
        Element A = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(AString)).getImmutable();
        String cString = skProp.getProperty("c"+device);
        Element c = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(cString)).getImmutable();
        String xString = skProp.getProperty("x"+device);
        Element x = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xString)).getImmutable();

        //generate the request message
        String T = String.valueOf(System.currentTimeMillis());
        Element r = bp.getZr().newRandomElement().getImmutable();
        Element R = P.powZn(r).getImmutable();
        byte[] H = sha1(A.toString()+c.toString()+R.toString()+Q.toString()+T);
        Element z = c.add(bp.getZr().newElementFromHash(H,0, H.length).mul(r.add(x)));
        skProp.setProperty("r"+device,Base64.getEncoder().withoutPadding().encodeToString(r.toBytes()));
        storePropToFile(skProp,skFileName);

        //send the authentication request message to Dj via open channel
        Properties msgProp = loadPropFromFile(msgFileName);
        msgProp.setProperty("ID"+device,Base64.getEncoder().withoutPadding().encodeToString(ID.toBytes()));
        msgProp.setProperty("z"+device,Base64.getEncoder().withoutPadding().encodeToString(z.toBytes()));
        msgProp.setProperty("A"+device,Base64.getEncoder().withoutPadding().encodeToString(A.toBytes()));
        msgProp.setProperty("c"+device,Base64.getEncoder().withoutPadding().encodeToString(c.toBytes()));
        msgProp.setProperty("R"+device,Base64.getEncoder().withoutPadding().encodeToString(R.toBytes()));
        msgProp.setProperty("T"+device,T);
        storePropToFile(msgProp,msgFileName);
    }

    public static void access2(String pairingParametersFileName, String pkFileName, String skFileName, String msgFileName, String deviceS, String deviceR) throws NoSuchAlgorithmException {
        /*
        step2. Dj->Di: MSG2={IDj,Aj,cj,Tj,Zj,Rj,SKVij,Qj}
         */

        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties pkProp = loadPropFromFile(pkFileName);
        String PString = pkProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PString)).getImmutable();
        String QCAString = pkProp.getProperty("Q_CA");
        Element Q_CA = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QCAString)).getImmutable();
        String QiString = pkProp.getProperty("Q"+deviceS);
        Element Qi = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QiString)).getImmutable();
        String QjString = pkProp.getProperty("Q"+deviceR);
        Element Qj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QjString)).getImmutable();



        Properties msgProp = loadPropFromFile(msgFileName);
        String IDiString = msgProp.getProperty("ID"+deviceS);
        Element IDi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(IDiString)).getImmutable();
        String AiString = msgProp.getProperty("A"+deviceS);
        Element Ai = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(AiString)).getImmutable();
        String ciString = msgProp.getProperty("c"+deviceS);
        Element ci = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ciString)).getImmutable();
        String RiString = msgProp.getProperty("R"+deviceS);
        Element Ri = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RiString)).getImmutable();
        String ziString = msgProp.getProperty("z"+deviceS);
        Element zi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(ziString)).getImmutable();
        String Ti = msgProp.getProperty("T"+deviceS);

        byte[] H1 = sha1(IDi.toString()+Ai.toString());
        Element Uj = Q_CA.add(Ai.powZn(bp.getZr().newElementFromHash(H1,0, H1.length)));

        if (!Uj.isEqual(P.powZn(ci))){
            System.out.println("verification fail!");
        }

        byte[] H2 = sha1(Ai.toString()+ci.toString()+Ri.toString()+Qi.toString()+Ti);
        Element Wj = P.powZn(ci).add(Ri.add(Qi).powZn(bp.getZr().newElementFromHash(H2,0, H2.length)));

        if (!Wj.isEqual(P.powZn(zi))){
            System.out.println("verification fail!");
        }
        //Generate the reply messages
        Properties skProp = loadPropFromFile(skFileName);
        String IDjString = skProp.getProperty("ID"+deviceR);
        Element IDj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(IDjString)).getImmutable();
        String AjString = skProp.getProperty("A"+deviceR);
        Element Aj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(AjString)).getImmutable();
        String cjString = skProp.getProperty("c"+deviceR);
        Element cj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(cjString)).getImmutable();
        String xjString = skProp.getProperty("x"+deviceR);
        Element xj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xjString)).getImmutable();

        Element rj = bp.getZr().newRandomElement().getImmutable();
        String Tj = String.valueOf(System.currentTimeMillis());
        Element Rj = P.powZn(rj);
        byte[] H3 = sha1(Aj.toString()+cj.toString()+Rj.toString()+Qj.toString()+Tj);
        Element zj = cj.add(bp.getZr().newElementFromHash(H3,0, H3.length).mul(rj.add(xj)));
        Element Bij = Ri.powZn(rj).getImmutable();
        Element Kij = Qi.powZn(xj).getImmutable();

        byte[] H4 = sha1(Bij.toString()+Kij.toString()+Ti+Tj+IDi.toString()+IDj.toString());
        Element SKij = bp.getZr().newElementFromHash(H4,0, H4.length);

        //save the session key with device Di
        skProp.setProperty("SK"+"_"+deviceR,Base64.getEncoder().withoutPadding().encodeToString(SKij.toBytes()));
        storePropToFile(skProp,skFileName);

        //send the authentication reply messages to Di via open channel
        msgProp.setProperty("ID"+deviceR,Base64.getEncoder().withoutPadding().encodeToString(IDj.toBytes()));
        msgProp.setProperty("z"+deviceR,Base64.getEncoder().withoutPadding().encodeToString(zj.toBytes()));
        msgProp.setProperty("A"+deviceR,Base64.getEncoder().withoutPadding().encodeToString(Aj.toBytes()));
        msgProp.setProperty("c"+deviceR,Base64.getEncoder().withoutPadding().encodeToString(cj.toBytes()));
        msgProp.setProperty("R"+deviceR,Base64.getEncoder().withoutPadding().encodeToString(Rj.toBytes()));
        msgProp.setProperty("T"+deviceR,Tj);
        storePropToFile(msgProp,msgFileName);
    }

    public static void access3(String pairingParametersFileName, String pkFileName, String skFileName, String msgFileName, String deviceS, String deviceR) throws NoSuchAlgorithmException {
        /*
        step3. Di->Dj: MSG3={SKVij',Ti'}
         */

        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties pkProp = loadPropFromFile(pkFileName);
        String PString = pkProp.getProperty("P");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PString)).getImmutable();
        String QCAString = pkProp.getProperty("Q_CA");
        Element Q_CA = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QCAString)).getImmutable();
        String QjString = pkProp.getProperty("Q"+deviceS);
        Element Qj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QjString)).getImmutable();
        String QiString = pkProp.getProperty("Q"+deviceR);
        Element Qi = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(QiString)).getImmutable();



        Properties msgProp = loadPropFromFile(msgFileName);
        String IDjString = msgProp.getProperty("ID"+deviceS);
        Element IDj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(IDjString)).getImmutable();
        String AjString = msgProp.getProperty("A"+deviceS);
        Element Aj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(AjString)).getImmutable();
        String cjString = msgProp.getProperty("c"+deviceS);
        Element cj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(cjString)).getImmutable();
        String RjString = msgProp.getProperty("R"+deviceS);
        Element Rj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RjString)).getImmutable();
        String zjString = msgProp.getProperty("z"+deviceS);
        Element zj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(zjString)).getImmutable();
        String Tj = msgProp.getProperty("T"+deviceS);
        String Ti = msgProp.getProperty("T"+deviceR);

        byte[] H1 = sha1(IDj.toString()+Aj.toString());
        Element Ui = Q_CA.add(Aj.powZn(bp.getZr().newElementFromHash(H1,0, H1.length)));

        if (!Ui.isEqual(P.powZn(cj))){
            System.out.println("verification fail!");
        }

        byte[] H2 = sha1(Aj.toString()+cj.toString()+Rj.toString()+Qj.toString()+Tj);
        Element Wi = P.powZn(cj).add(Rj.add(Qj).powZn(bp.getZr().newElementFromHash(H2,0, H2.length)));

        if (!Wi.isEqual(P.powZn(zj))){
            System.out.println("verification fail!");
        }

        //Generate the session key
        Properties skProp = loadPropFromFile(skFileName);
        String riString = skProp.getProperty("r"+deviceR);
        Element ri = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(riString)).getImmutable();
        String xiString = skProp.getProperty("x"+deviceR);
        Element xi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xiString)).getImmutable();
        String IDiString = skProp.getProperty("ID"+deviceR);
        Element IDi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(IDiString)).getImmutable();

        Element Bij = Rj.powZn(ri).getImmutable();
        Element Kij = Qj.powZn(xi).getImmutable();

        byte[] H4 = sha1(Bij.toString()+Kij.toString()+Ti+Tj+IDi.toString()+IDj.toString());
        Element SKij = bp.getZr().newElementFromHash(H4,0, H4.length);
        //save the session key with device Di
        skProp.setProperty("SK"+"_"+deviceR,Base64.getEncoder().withoutPadding().encodeToString(SKij.toBytes()));
        storePropToFile(skProp,skFileName);
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
        String dir = "./data/Das_data/";
        String pkFile = dir + "pk.properties";
        String mskFile = dir + "msk.properties";
        String skFile = dir + "sk.properties";
        String msgFile = dir + "msg.properties";

        String deviceS = "Di";
        String deviceR = "Dj";
        //setup(pairingParametersFileName,pkFile,mskFile);
        //deviceRegistration(pairingParametersFileName,pkFile,mskFile,skFile,deviceR);

        for (int i = 0; i < 10; i++) {
            long start = System.currentTimeMillis();
            access1(pairingParametersFileName,pkFile,skFile,msgFile,deviceS);
            access2(pairingParametersFileName,pkFile,skFile,msgFile,deviceS,deviceR);
            access3(pairingParametersFileName,pkFile,skFile,msgFile,deviceR,deviceS);
            long end = System.currentTimeMillis();
            System.out.println(end-start);
        }



    }
}
