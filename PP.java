package my_test;

import java.math.BigInteger;
import java.util.HashMap;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
public class PP {
	ElementPowPreProcessing g;
	ElementPowPreProcessing egg;
    
	Pairing bp;
	Field G1;
	Field Zq;
	HashMap<String,Element> hash;
	
	PP(int rBit, int qBit) {
	    TypeACurveGenerator pg = new TypeACurveGenerator(rBit, qBit); // A types symmetric prime order group
	    PairingParameters pp = pg.generate();

	    this.bp = PairingFactory.getPairing(pp);

	    this.G1 = bp.getG1();
	    this.Zq = bp.getZr();
	    Element gg= G1.newRandomElement();
	    
	    this.g = gg.getElementPowPreProcessing();//getImmutable();
	    
	    //ElementPowPreProcessing gg = ;
	    this.egg = bp.pairing(gg, gg).getElementPowPreProcessing();
	    this.hash = new HashMap<String, Element>();

	    // Print the size of G1 and Zq elements
	}

	public static long getSizeInBytes(Object obj) throws Exception {
	    if (obj instanceof Element) {
	        // Use JPBC's built-in serialization method for Elements
	        return ((Element) obj).toBytes().length;
	    } else if (obj instanceof Field) {
	        // Fields themselves may not be serializable, but elements from the field are
	        Element tmp = ((Field) obj).newRandomElement();
	        return tmp.toBytes().length;
	    } else {
	        throw new IllegalArgumentException("Object type not supported for size calculation");
	    }
	}


	//public Element getg() {
	//	return this.g.duplicate();
	//}
	public Element g_(Element z) {
		return g.powZn(z);
	}
	public Element g_(BigInteger z) {
		return g.pow(z);
	}
	public Element egg_(Element z) {
		return egg.powZn(z);
	}
	public Element egg_(String z) {
		return egg.pow(new BigInteger(z));
	}
	public Element egg(Element z) {
		return this.egg(z);
	}
	public Element e(Element ga,Element gb) {
		return bp.pairing(ga, gb);
	}
	public Element H(String RID) {
		Element hr=hash.get(RID);
		if(hr==null) {
			hr=g_(Zq.newRandomElement().getImmutable());
			hash.put(RID,hr);
		}
		return hr;
	}
	public Element generateZr() {
		return Zq.newRandomElement().getImmutable();
	}
	
	public static void testPP(int rBit, int qBit) {

		double pptime=0;
		long time0 = System.nanoTime();
		for(int i=0;i<100;i++) {
			PP pp=new PP(rBit,qBit);
		}
		
	    
	    long time1 = System.nanoTime();
	    pptime += (time1 - time0) / 1_000_000.0;
		
		System.out.println("generate a PP in "+pptime/100+"ms");
		
	}
	public static void testexp(int rBit, int qBit) {

		double exptime=0;
		PP pp=new PP(rBit,qBit);
		long time0 = System.nanoTime();
		for(int i=0;i<100;i++) {
			Element rE=pp.g_(pp.generateZr());
		}
		
	    
	    long time1 = System.nanoTime();
	    exptime += (time1 - time0) / 1_000_000.0;
		
		System.out.println("exp on g1 in "+exptime/100+"ms");
		
	}
	public static void testpairing(int rBit, int qBit) {

		double pairtime=0;
		PP pp=new PP(rBit,qBit);
		
		Element ga=pp.g_(pp.generateZr());
		Element gb=pp.g_(pp.generateZr());
		long time0 = System.nanoTime();
		for(int i=0;i<100;i++) {
			Element rE=pp.bp.pairing(ga, gb);
		}
		
	    
	    long time1 = System.nanoTime();
	    pairtime += (time1 - time0) / 1_000_000.0;
		
		System.out.println("pairing in "+pairtime/100+"ms");
		
	}
	public static void testgtexp(int rBit, int qBit) {

		double pairtime=0;
		PP pp=new PP(rBit,qBit);
		long time0 = System.nanoTime();
		for(int i=0;i<100;i++) {
			Element rE=pp.egg_(pp.generateZr());
		}
		
	    
	    long time1 = System.nanoTime();
	    pairtime += (time1 - time0) / 1_000_000.0;
		
		System.out.println("exp on gt in "+pairtime/100+"ms");
		
	}
	public static void testPrime() {
		int rBit=128;
		int qBit=512;
		testPP(rBit,qBit);
		testexp(rBit,qBit);
		testgtexp(rBit,qBit);
		testpairing(rBit,qBit);
	}
	public static void testSize() {
		PP pp=new PP(128,512);
		try {
	        System.out.println("Size of an element in G1: " + getSizeInBytes(pp.g_(pp.generateZr())) + " bytes");
	        System.out.println("Size of an element in Gt: " + getSizeInBytes(pp.egg_(pp.generateZr())) + " bytes");
	        System.out.println("Size of an element in Zq: " + getSizeInBytes(pp.Zq) + " bytes");
	    } catch (Exception e) {
	        e.printStackTrace();
	    }
	}
	public static void main(String arg[]) {
		testSize();
		testPrime();
		
		
//		Size of an element in G1: 130 bytes
//		Size of an element in Gt: 130 bytes
//		Size of an element in Zq: 16 bytes
		//testPrime();
		
	}
}
