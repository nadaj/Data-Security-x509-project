package main;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class Main {

	public static String toUTC(String date)
	{
		return date.substring(8, 10) + date.substring(3, 5) + date.substring(0,2) 
						+ date.substring(10, 12) + date.substring(13, 15) + date.substring(16, 18) + "Z";
	}
	
	public static String toGMT(String date)
	{
		return date.substring(6, 10) + date.substring(3, 5) + date.substring(0,2) 
			+ date.substring(10, 12) + date.substring(13, 15) + date.substring(16, 18) + "Z";
	}
	
	public static java.security.cert.Certificate importCertificate(String alias, String keypass, String filename) 
			throws Exception
	{
		KeyStore keystore = KeyStore.getInstance("pkcs12");
		FileInputStream inStream = new FileInputStream(filename);
	    keystore.load(inStream, keypass.toCharArray());
	    inStream.close();
		
		return keystore.getCertificate(alias);
	}
	
	public static Date formatDate(String date) throws ParseException
	{
		SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyyHH:mm:ss'Z'");
		SimpleDateFormat dateFormatUTC = new SimpleDateFormat("yyMMddHHmmss'Z'");
		SimpleDateFormat dateFormatGMT = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
		
		Calendar cal = Calendar.getInstance();
		cal.setTime(dateFormat.parse(date));
		
		if (cal.get(Calendar.YEAR) < 2050)	// UTC time
		{
			return dateFormatUTC.parse(toUTC(date));
		}
		else								// Generalized time
		{
			return dateFormatGMT.parse(toGMT(date));
		}
	}
	
	public static void main(String[] args) {
		int option = 0;
		Scanner in = new Scanner(System.in);
		
		while (true)
		{
			System.out.println("\nOdaberite funkcionalnost:");
			System.out.println("0. Kraj");
			System.out.println("1. Generisanje novog para kljuceva za sertifikat");
			System.out.println("2. Dohvatanje kljuca");
			System.out.println("3. Potpisivanje sertifikata");
			System.out.println("4. Izvoz kreiranog sertifikata");
			System.out.println("-------------------------------------------");
			option = in.nextInt();
			if (option == 0) break;
			switch(option)
			{
				case 1: {
					try {
						System.out.println("\nVelicina kljuca:");
						int keysize = in.nextInt();
						if (keysize < 1024) keysize = 1024;
						else if (keysize > 4096) keysize = 4096;
						
						System.out.println("Period vazenja - OD (u formatu dd-MM-yyyy HH:mm:ss):");
						String notBefore = in.next();
						notBefore += in.next() + "Z";
						
						SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyyHH:mm:ss'Z'");
						Date date1 = formatDate(notBefore);
						System.out.println(date1.toString());
						
						System.out.println("Period vazenja - DO (u formatu dd-MM-yyyy HH:mm:ss ili . ako nema):");
						String notAfter = in.next();
						
						Date date2;
						SimpleDateFormat dateFormatGMT = new SimpleDateFormat("yyyyMMddHHmmss'Z'");
						
						if (notAfter.compareTo(".") == 0)
						{
							date2 = dateFormatGMT.parse("99991231235959Z");
						}
						else
						{
							notAfter += in.next() + "Z";

							if (dateFormat.parse(notAfter).before(dateFormat.parse(notBefore)))
							{
								System.out.println("Nisu ispravni uneti datumi.");
								break;
							}
							
							date2 = formatDate(notAfter);
							System.out.println(date2.toString());
						}
						
						System.out.println("Serijski broj:");
						BigInteger serialNumber = in.nextBigInteger();
						if (serialNumber.signum() == -1 || serialNumber.signum() == 0 || serialNumber.bitLength() > 160)
						{
							System.out.println("Serijski broj mora da bude pozitivan ceo broj u opsegu od 0 do 2^160 - 1.");
							break;
						}
						
						X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
						System.out.println("Informacije o korisniku (CN, OU, O, L, ST, C, E):");
						System.out.println("CN:");
					    nameBuilder.addRDN(BCStyle.CN, in.next());
						System.out.println("OU:");
						nameBuilder.addRDN(BCStyle.OU, in.next());
						System.out.println("O:");
						nameBuilder.addRDN(BCStyle.O, in.next());
						System.out.println("L:");
						nameBuilder.addRDN(BCStyle.L, in.next());
						System.out.println("ST:");
						nameBuilder.addRDN(BCStyle.ST, in.next());
						System.out.println("C:");
						nameBuilder.addRDN(BCStyle.C, in.next());
						System.out.println("E:");
						nameBuilder.addRDN(BCStyle.E, in.next());
						
						// init key generator
						Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
						KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
						SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
						keyGen.initialize(keysize, random);
						
						// generate keypair
						KeyPair pair = keyGen.generateKeyPair();
						PrivateKey privKey = pair.getPrivate();
						PublicKey pubKey = pair.getPublic();
					  
					    X500Name issuerName = nameBuilder.build();
					    X500Name subject = issuerName;
					    X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuerName, serialNumber,
					    		date1, date2, subject, pubKey);
					    
						// EKSTENZIJE : MORA BAR 1
						int selected = 0;
						System.out.println("Osnovna ogranicenja: \nPrisutno[0/1]:");
						int temp = in.nextInt();
						boolean critical, criticalBasic = false;
						boolean cA = false;
						int pathLenConstraint = -1;
						if (temp == 1)
						{
							selected++;
							System.out.println("Kriticno[true/false]:");
							critical = in.nextBoolean();
							criticalBasic = critical;
							System.out.println("cA[true/false]:");
							cA = in.nextBoolean();
							if (cA)
							{
								System.out.println("pathLenConstraint[-1-not present/vrednost]:");
								pathLenConstraint = in.nextInt();
								if (pathLenConstraint < -1)
								{
									System.out.println("Osnovna ogranicenja: parametar pathLenConstraint mora biti ceo broj > 0.");
									break;
								}
								if (pathLenConstraint == -1)
									certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"),
									        critical,
									        new BasicConstraints(cA));
							}
							else
							{
								certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"),
								        critical,
								        new BasicConstraints(cA));
							}
						}
						
						System.out.println("Alternativna imena izdavaoca sertifikata: \nPrisutno[0/1]:");
						temp = in.nextInt();
						if (temp == 1)
						{
							selected++;
							critical = false;
							System.out.println("Tip alternativnog imena	[0 - otherName, 1 - rfc822, 2 - dNSName, 3 - x400Address"
									+ ", 4 - directoryName, 5 - ediPartyName, 6 - uniformResourceIdentifier, 7 - iPAddress, 8 - registeredID :");
							int altNameType = in.nextInt();
							System.out.println("Alternativno ime:");
							certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.18"),
							        critical,
							        new GeneralNames(new GeneralName(altNameType, in.next())));
						}
						
						System.out.println("Koriscenje kljuca: \nPrisutno[0/1]:");
						temp = in.nextInt();
						if (temp == 1)
						{
							selected++;
							critical = true;
							int keyUsageValue = 0;
							System.out.println("digitalSignature[0/1]:");
							if (in.nextInt() == 1)
								keyUsageValue |= KeyUsage.digitalSignature;
							
							System.out.println("nonRepudiation[0/1]:");
							if (in.nextInt() == 1)
								keyUsageValue |= KeyUsage.nonRepudiation;
							
							System.out.println("keyEncipherment[0/1]:");
							if (in.nextInt() == 1)
								keyUsageValue |= KeyUsage.keyEncipherment;
							
							System.out.println("dataEncipherment[0/1]:");
							if (in.nextInt() == 1)
								keyUsageValue |= KeyUsage.dataEncipherment;
							
							System.out.println("keyAgreement[0/1]:");
							if (in.nextInt() == 1)
								keyUsageValue |= KeyUsage.keyAgreement;
							
							if(cA)
							{
								System.out.println("keyCertSign[0/1]:");
								if (in.nextInt() == 1)
								{
									if (pathLenConstraint != -1)
										certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"),
									        criticalBasic,
									        new BasicConstraints(pathLenConstraint));
									
									keyUsageValue |= KeyUsage.keyCertSign;
								}
								else
								{
									if (pathLenConstraint != -1)
									{
										System.out.println("Da bi se uneo pathLenConstraint, moraju da bude cA i keyCertSign true.");
										break;
									}
								}
							}
							
							System.out.println("cRLSign[0/1]:");
							if (in.nextInt() == 1)
								keyUsageValue |= KeyUsage.cRLSign;
							
							System.out.println("encipherOnly[0/1]:");
							if (in.nextInt() == 1)
								keyUsageValue |= KeyUsage.encipherOnly;
							
							System.out.println("decipherOnly[0/1]:");
							if (in.nextInt() == 1)
								keyUsageValue |= KeyUsage.decipherOnly;
							
							if (keyUsageValue == 0)
							{
								System.out.println("Key Usage mora imati vrednost razlicitu od 0.");
								break;
							}
							certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.15"),
							        critical,
							        new KeyUsage(keyUsageValue));
						}
						
						if (selected == 0)
						{
							System.out.println("Mora da se definise barem 1 ogranicenje.");
							break;
						}
						
						KeyStore keystore = KeyStore.getInstance("pkcs12");	// drugi argument moze da bude provider
						String keypass = "password";
						keystore.load(null, keypass.toCharArray());
						
						String defaultalias = "keystore";
						java.security.cert.X509Certificate cert = new JcaX509CertificateConverter().
								setProvider("BC").getCertificate(certBuilder.build(
								new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey)));
						keystore.setKeyEntry(defaultalias, privKey, keypass.toCharArray(), 
								new java.security.cert.X509Certificate[]{cert});
						FileOutputStream outStream = new FileOutputStream ("mykeystore.p12");
						keystore.store(outStream, keypass.toCharArray());
						outStream.close();
						
//						cert.verify(pubKey);
//						System.out.println(privKey.toString());
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
				break;
				case 2:
				{
					try {
						KeyStore keystore = KeyStore.getInstance("pkcs12");
						String keypass = "password";
						FileInputStream inStream = new FileInputStream("mykeystore.p12");
					    keystore.load(inStream, keypass.toCharArray());
					    inStream.close();
						
						String defaultalias = "keystore";
						PrivateKey privKey = (PrivateKey) keystore.getKey(defaultalias, keypass.toCharArray());
						System.out.println(privKey.toString());
						
						java.security.cert.Certificate certif = keystore.getCertificate(defaultalias);
						System.out.println(certif.toString());
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
				break;
				case 3:
				{
					try {
						KeyStore keystore = KeyStore.getInstance("pkcs12");
						String keypass = "password";
						FileInputStream inStream = new FileInputStream("mykeystore.p12");
					    keystore.load(inStream, keypass.toCharArray());
					    inStream.close();
						
						String defaultalias = "keystore";
						PrivateKey privKey = (PrivateKey) keystore.getKey(defaultalias, keypass.toCharArray());
						java.security.cert.Certificate certif = keystore.getCertificate(defaultalias);
						
						//ContentSigner signGen = new JcaContentSignerBuilder("SHA1withRSA").build(CAPrivateKey);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
				break;
				case 4:
				{
					try {
						java.security.cert.Certificate certif = importCertificate("keystore", "password", "mykeystore.p12");
						 File file = new File("encodedcert.cer");
						 byte[] buf = certif.getEncoded();
						 
						 FileOutputStream os = new FileOutputStream(file);
						 os.write(buf);
						 
						 Writer wr = new OutputStreamWriter(os, Charset.forName("UTF-8"));
						 wr.write(Base64.getEncoder().withoutPadding().encodeToString(buf));
						 wr.flush();
						 os.close();
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
				break;
			}
		}
		in.close();
	}

}
