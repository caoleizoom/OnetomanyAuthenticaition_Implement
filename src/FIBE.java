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


public class FIBE {
    public static void setup(String pairingParametersFileName, int U, int d, String pkFileName, String mskFileName) {
        /*
        U：属性集合
        d：门限值
        pkFileName：存放公钥
        mskFileName：存放私钥
         */

        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Element g = bp.getG1().newRandomElement().getImmutable();
        //云服务器私钥
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element C_pub = g.powZn(s).getImmutable();
        Properties mskProp = new Properties();
        Properties pkProp = new Properties();
        //属性表示为1，2，3，...，U
        //选择t_1,...,t_n+1
        for (int i = 1; i <= U+1; i++){
            Element t = bp.getG1().newRandomElement().getImmutable();
            mskProp.setProperty("t" + i, Base64.getEncoder().withoutPadding().encodeToString(t.toBytes()));
        }
        //另外选取一个随机数y，计算e(g,g)^y
        Element y = bp.getZr().newRandomElement().getImmutable();
        Element g1 = g.powZn(y).getImmutable();
        Element g2 = bp.getG1().newRandomElement().getImmutable();
        Element T_pub = bp.pairing(g1, g2).getImmutable();

        mskProp.setProperty("y", Base64.getEncoder().withoutPadding().encodeToString(y.toBytes()));
        mskProp.setProperty("s", Base64.getEncoder().withoutPadding().encodeToString(s.toBytes()));
        pkProp.setProperty("T_pub", Base64.getEncoder().withoutPadding().encodeToString(T_pub.toBytes()));
        pkProp.setProperty("C_pub", Base64.getEncoder().withoutPadding().encodeToString(C_pub.toBytes()));
        pkProp.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        pkProp.setProperty("g1", Base64.getEncoder().withoutPadding().encodeToString(g1.toBytes()));
        pkProp.setProperty("g2", Base64.getEncoder().withoutPadding().encodeToString(g2.toBytes()));
        //注意区分数据类型。上面写的数据类型群元素，因此使用了Base64编码。
        //d在实际应用中定义为一个int类型，直接用Integer.toString方法转字符串
        pkProp.setProperty("d", Integer.toString(d));
        pkProp.setProperty("U", Integer.toString(U));

        storePropToFile(mskProp, mskFileName);
        storePropToFile(pkProp, pkFileName);
    }

    public static void keygen(String pairingParametersFileName, int[] userAttList, String pkFileName, String mskFileName, String skFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);

        Properties pkProp = loadPropFromFile(pkFileName);
        String gString = pkProp.getProperty("g");
        String g2String = pkProp.getProperty("g2");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        Element g2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g2String)).getImmutable();
        String dString = pkProp.getProperty("d");
        String UString = pkProp.getProperty("U");
        int d = Integer.parseInt(dString);
        int U = Integer.parseInt(dString);

        Properties mskProp = loadPropFromFile(mskFileName);
        String yString = mskProp.getProperty("y");
        Element y = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(yString)).getImmutable();

        //d-1次多项式表示为q(x)=coef[0] + coef[1]*x^1 + coef[2]*x^2 + coef[d-1]*x^(d-1)
        //多项式的系数的数据类型为Zr Element，从而是的后续相关计算全部在Zr群上进行
        //通过随机选取coef参数，来构造d-1次多项式q(x)。约束条件为q(0)=y。
        Element[] coef = new Element[d];
        coef[0] = y;
        for (int i = 1; i < d; i++){
            coef[i] = bp.getZr().newRandomElement().getImmutable();
        }

        Properties skProp = new Properties();
        //计算每个属性对应的私钥g^(q/t)，q是多项式在该属性位置的值，t是属性对应的主密钥
        for (int att : userAttList) {
            Element r = bp.getZr().newRandomElement().getImmutable();
            Element q = qx(bp.getZr().newElement(att), coef, bp.getZr()).getImmutable();
            Element D = g2.powZn(q).mul(Tx(att,U).powZn(r));
            Element di = g.powZn(r.negate());
            skProp.setProperty("D"+att, Base64.getEncoder().withoutPadding().encodeToString(D.toBytes()));
            skProp.setProperty("d"+att, Base64.getEncoder().withoutPadding().encodeToString(di.toBytes()));
        }
        //将用户属性列表也添加在私钥中
        skProp.setProperty("userAttList", Arrays.toString(userAttList));
        storePropToFile(skProp, skFileName);
    }

    //发送方生成认证消息
    public static void genMsg(String pairingParametersFileName, int[] userAttList, String pkFileName, String skFileName, String msgFileName) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFileName);
        String gString = pkProp.getProperty("g");
        String g2String = pkProp.getProperty("g2");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        Element g2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g2String)).getImmutable();

        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Element beta = bp.getZr().newRandomElement().getImmutable();
        String T = String.valueOf(System.currentTimeMillis());
        byte [] h1 = sha1(userAttList.toString()+T);
        Element A0 = bp.getZr().newElementFromHash(h1,0, h1.length);
        Element A1 = alpha.add(beta.mul(A0));
        Element Z = g2.powZn(beta).getImmutable();

        Properties skProp = loadPropFromFile(skFileName);
        Properties msgProp = new Properties();
        for( int att : userAttList ){
            String DString = skProp.getProperty("D"+att);
            String dString = skProp.getProperty("d"+att);
            Element D = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DString)).getImmutable();
            Element d = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(dString)).getImmutable();
            Element s = bp.getZr().newRandomElement().getImmutable();

            Element M = D.mul(g.powZn(s).mul(g2.powZn(alpha.negate()))).getImmutable();
            Element N = d;
            Element C = g.powZn(s.negate()).mul(g2.powZn(beta.negate()));

            msgProp.setProperty("M"+att, Base64.getEncoder().withoutPadding().encodeToString(M.toBytes()));
            msgProp.setProperty("N"+att, Base64.getEncoder().withoutPadding().encodeToString(N.toBytes()));
            msgProp.setProperty("C"+att, Base64.getEncoder().withoutPadding().encodeToString(C.toBytes()));
        }
        msgProp.setProperty("A1", Base64.getEncoder().withoutPadding().encodeToString(A1.toBytes()));
        msgProp.setProperty("Z", Base64.getEncoder().withoutPadding().encodeToString(Z.toBytes()));
        msgProp.setProperty("T", T);
        msgProp.setProperty("senderAttList", Arrays.toString(userAttList));
        storePropToFile(msgProp,msgFileName);
    }



    //接收方认证
    public static void AttrCheck(String pairingParametersFileName, String  mskFileName, int [] userAttList, String pkFile, String msgFile) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFile);
        String dString = pkProp.getProperty("d");
        String gString = pkProp.getProperty("g");
        String g2String = pkProp.getProperty("g2");
        String T_pubString = pkProp.getProperty("T_pub");
        String C_pubString = pkProp.getProperty("C_pub");
        //门限
        int d = Integer.parseInt(dString);
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        Element g2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g2String)).getImmutable();
        Element T_pub = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(T_pubString)).getImmutable();
        Element C_pub = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(C_pubString)).getImmutable();


        Properties msgProp = loadPropFromFile(msgFile);
        String senderAttListString = msgProp.getProperty("senderAttList");
        int[] senderAttList = Arrays.stream(senderAttListString.substring(1, senderAttListString.length()-1).split(",")).map(String::trim).mapToInt(Integer::parseInt).toArray();
        int[] intersectionAttList = intersection(senderAttList, userAttList);
        System.out.println("重合属性列表：" + Arrays.toString(intersectionAttList));
        System.out.println("重合属性个数为：" + intersectionAttList.length);
        if (intersectionAttList.length < d) {
            System.out.println("不满足解密门限，无法验证！");
        }
        //从两个列表中的重合项中取前d项
        int[] decAttList = Arrays.copyOfRange(intersectionAttList, 0, d);
        System.out.println("前d项属性列表：" + Arrays.toString(decAttList));

        //取出身份验证消息
        String A1String = msgProp.getProperty("A1");
        String ZString = msgProp.getProperty("Z");
        String T = msgProp.getProperty("T");
        Element A1 = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(A1String)).getImmutable();
        Element Z = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ZString)).getImmutable();

        byte [] h1_hash = sha1(senderAttList.toString()+T);
        Element A0_ = bp.getZr().newElementFromHash(h1_hash,0, h1_hash.length);

        Element denominator = bp.getGT().newOneElement().getImmutable();
        for( int att : decAttList ){
            String MString = msgProp.getProperty("M"+att);
            Element M = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(MString)).getImmutable();

            String NString = msgProp.getProperty("N"+att);
            Element N = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(NString)).getImmutable();

            String CString = msgProp.getProperty("C"+att);
            Element C = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(CString)).getImmutable();

            Element delta = lagrange(att,decAttList,0,bp.getZr()).getImmutable();
            denominator = denominator.mul(
                    bp.pairing(g,M).mul(
                            bp.pairing(Tx(att,20),N).mul(
                                    bp.pairing(g,C).mul(
                                            bp.pairing(Z.powZn(A0_.negate().add(bp.getZr().newOneElement())).mul(
                                                    g2.powZn(A1)),g))))
                    ).powZn(delta);
        }
        String result;
        if (denominator.isEqual(T_pub)){
            System.out.println("身份验证成功!!!");
            result = "pass";
        }else {
            System.out.println("身份验证失败!!!");
            result = "fail";
        }

        Properties mskProp = loadPropFromFile(mskFileName);
        String sString  = mskProp.getProperty("s");
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sString)).getImmutable();
        Element r = bp.getZr().newRandomElement().getImmutable();
        Element R = g.powZn(r).getImmutable();
        byte[] H = sha1(userAttList.toString()+R.toString()+C_pub.toString()+result);
        Element h = bp.getZr().newElementFromHash(H,0, H.length);
        Element sig = r.add(s.mul(h));
        msgProp.setProperty("result",Base64.getEncoder().withoutPadding().encodeToString(result.getBytes()));
        msgProp.setProperty("sig",Base64.getEncoder().withoutPadding().encodeToString(sig.toBytes()));
        msgProp.setProperty("R",Base64.getEncoder().withoutPadding().encodeToString(R.toBytes()));
        storePropToFile(msgProp,msgFile);
    }

    public static void genSessionKey(String pairingParametersFileName,int [] userAttList, String pkFile, String msgFile, String skFile) throws NoSuchAlgorithmException {
        Pairing bp = PairingFactory.getPairing(pairingParametersFileName);
        Properties pkProp = loadPropFromFile(pkFile);
        String gString = pkProp.getProperty("g");
        String g2String = pkProp.getProperty("g2");
        Element g =  bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gString)).getImmutable();
        Element g2 =  bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g2String)).getImmutable();
        String C_pubString = pkProp.getProperty("C_pub");
        Element C_pub =  bp.getG1().newElementFromBytes(Base64.getDecoder().decode(C_pubString)).getImmutable();


        Properties msgProp = loadPropFromFile(msgFile);
        String senderAttListString = msgProp.getProperty("senderAttList");
        int[] senderAttList = Arrays.stream(senderAttListString.substring(1, senderAttListString.length()-1).split(",")).map(String::trim).mapToInt(Integer::parseInt).toArray();
        String result = msgProp.getProperty("result");
        String sigString = msgProp.getProperty("sig");
        Element sig =  bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sigString)).getImmutable();
        String RString = msgProp.getProperty("R");
        Element R = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RString)).getImmutable();

        byte[] H1 = sha1(userAttList.toString()+R.toString()+C_pub.toString()+result);
        Element h = bp.getZr().newElementFromHash(H1,0, H1.length);
        Properties skProp = loadPropFromFile(skFile);
        if (g.powZn(sig).isEqual(R.add(C_pub.powZn(h)))){
            System.out.println("签名验证成功");
            if (result == "pass"){
                System.out.println("直接丢弃消息！");
            }else{
                String ZString = msgProp.getProperty("Z");
                Element Z =  bp.getG1().newElementFromBytes(Base64.getDecoder().decode(ZString)).getImmutable();
                Element beta = bp.getZr().newRandomElement().getImmutable();
                Element Z_ = g2.powZn(beta).getImmutable();
                byte[] H2 = sha1(senderAttListString.toString()+userAttList.toString()+Z.toString()+Z_.toString()+Z.powZn(beta).toString());
                Element k = bp.getZr().newElementFromHash(H2,0, H2.length);
                skProp.setProperty("beta",Base64.getEncoder().withoutPadding().encodeToString(beta.toBytes()));
                skProp.setProperty("k",Base64.getEncoder().withoutPadding().encodeToString(k.toBytes()));
                storePropToFile(skProp,skFile);
            }
        }
    }



    public  static Element Tx(int x, int U){
        Pairing bp = PairingFactory.getPairing("./a.properties");

        Properties mskProp = loadPropFromFile("data/FIBE_data/msk.properties");
        Properties pkProp = loadPropFromFile("data/FIBE_data/pk.properties");
        String g2String = pkProp.getProperty("g2");
        Element g2 = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g2String)).getImmutable();
        int n = U + 1;
        int[] N = IntStream.rangeClosed(1, n).toArray();
        Element T = bp.getG1().newOneElement().getImmutable();
        for (int i = 1; i <= n; i++) {
            String tString = mskProp.getProperty("t" + i);
            Element t = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(tString)).getImmutable();
            Element delta = lagrange(i,N,x, bp.getZr());
            T = T.mul(t.powZn(delta));
        }
        int c = (int) Math.pow(x,U);
        BigInteger C = BigInteger.valueOf(c);
        T = T.mul(g2.pow(C));
        return T;
    }



    //计算由coef为系数确定的多项式qx在点x处的值，注意多项式计算在群Zr上进行
    public static Element qx(Element x, Element[] coef, Field Zr){
        Element res = coef[0];
        for (int i = 1; i < coef.length; i++){
            Element exp = Zr.newElement(i).getImmutable();
            //x一定要使用duplicate复制使用，因为x在每一次循环中都要使用，如果不加duplicte，x的值会发生变化
            res = res.add(coef[i].mul(x.duplicate().powZn(exp)));
        }
        return res;
    }


    //求两个数组的交集
    public static int[] intersection(int[] nums1, int[] nums2) {
        Arrays.sort(nums1);
        Arrays.sort(nums2);
        int length1 = nums1.length, length2 = nums2.length;
        int[] intersection = new int[length1 + length2];
        int index = 0, index1 = 0, index2 = 0;
        while (index1 < length1 && index2 < length2) {
            int num1 = nums1[index1], num2 = nums2[index2];
            if (num1 == num2) {
                // 保证加入元素的唯一性
                if (index == 0 || num1 != intersection[index - 1]) {
                    intersection[index++] = num1;
                }
                index1++;
                index2++;
            } else if (num1 < num2) {
                index1++;
            } else {
                index2++;
            }
        }
        return Arrays.copyOfRange(intersection, 0, index);
    }

    //拉格朗日因子计算 i是集合S中的某个元素，x是目标点的值
    public static Element lagrange(int i, int[] S, int x, Field Zr) {
        Element res = Zr.newOneElement().getImmutable();
        Element iElement = Zr.newElement(i).getImmutable();
        Element xElement = Zr.newElement(x).getImmutable();
        for (int j : S) {
            if (i != j) {
                //注意：在循环中重复使用的项一定要用duplicate复制出来使用
                //这儿xElement和iElement重复使用，但因为前面已经getImmutable所以可以不用duplicate
                Element numerator = xElement.sub(Zr.newElement(j));
                Element denominator = iElement.sub(Zr.newElement(j));
                res = res.mul(numerator.div(denominator));
            }
        }
        return res;
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

    //程序入口
    public static void main(String[] args) throws NoSuchAlgorithmException {
        int d = 6;
        int U = 20;

        String pairingParametersFileName = "./a.properties";
        String dir = "./data/FIBE_data/";
        String pkFile = dir + "pk.properties";
        String mskFile = dir + "msk.properties";
        String sk1File = dir + "sk1.properties";
        String sk2File = dir + "sk2.properties";
        String msgFile = dir + "msg.properties";
        int[] veh1AttList = {1, 5, 3, 6, 10, 11, 14, 16, 17, 22, 26, 27};
        int[] veh2AttList = {1, 4, 3, 7, 10, 11, 12, 16, 17, 21, 25, 27};
        //setup(pairingParametersFileName,U,d,pkFile,mskFile);
        //keygen(pairingParametersFileName,veh2AttList,pkFile,mskFile,sk2File);
        /*
        for (int i = 0; i < 10; i++) {
            long start = System.currentTimeMillis();
            genMsg(pairingParametersFileName,veh1AttList,pkFile,sk1File,msgFile);
            long end = System.currentTimeMillis();
            System.out.println(end-start);
        }
        */
        AttrCheck(pairingParametersFileName,mskFile,veh2AttList,pkFile,msgFile);

        for (int i = 0; i < 10; i++) {
            long start = System.currentTimeMillis();
            genSessionKey(pairingParametersFileName,veh2AttList,pkFile,msgFile,sk2File);
            long end = System.currentTimeMillis();
            System.out.println(end-start);
        }



    }
}