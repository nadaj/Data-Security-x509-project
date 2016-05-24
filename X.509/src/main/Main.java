package main;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.*;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERGeneralString;
import org.bouncycastle.asn1.DEROctetString;
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
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.IPAddress;
import org.bouncycastle.util.io.pem.PemObject;

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
		try {
			KeyStore keystore = KeyStore.getInstance("pkcs12");	// drugi argument moze da bude provider
			String keypass = "password";
			
			File file = new File("keys");
			if (file.length() != 0)
			{
				FileInputStream inputStream = new FileInputStream("keys");
				keystore.load(inputStream, keypass.toCharArray());
				inputStream.close();
			}
			else
			{
				keystore.load(null, keypass.toCharArray());
			}
			
			while (true)
			{
				System.out.println("Velicina keystore:" + keystore.size());
				System.out.println("\nOdaberite funkcionalnost:");
				System.out.println("0. Kraj");
				System.out.println("1. Generisanje novog para kljuceva za sertifikat");
				System.out.println("2. Uvoz/Izvoz kljuceva");
				System.out.println("3. Potpisivanje sertifikata");
				System.out.println("4. Izvoz kreiranog sertifikata");
				System.out.println("-------------------------------------------");
				option = in.nextInt();
				if (option == 0) break;
				switch(option)
				{
					case 1: {
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
						
						Enumeration<String> enumeration = keystore.aliases();
				        while(enumeration.hasMoreElements()) {
				            String alias = (String)enumeration.nextElement();
				            java.security.cert.Certificate certif = keystore.getCertificate(alias);
				            if (serialNumber.equals(((X509Certificate)certif).getSerialNumber()))
				            	throw new Exception("Vec postoji sertifikat sa istim serijskim brojem.");
				        }
						
						X500NameBuilder nameBuilder = new X500NameBuilder(BCStyle.INSTANCE);
						System.out.println("Informacije o korisniku (CN, OU, O, L, ST, C, E):");
						in.nextLine();
						System.out.println("CN:");
					    nameBuilder.addRDN(BCStyle.CN, in.nextLine());
						System.out.println("OU:");
						nameBuilder.addRDN(BCStyle.OU, in.nextLine());
						System.out.println("O:");
						nameBuilder.addRDN(BCStyle.O, in.nextLine());
						System.out.println("L:");
						nameBuilder.addRDN(BCStyle.L, in.nextLine());
						System.out.println("ST:");
						nameBuilder.addRDN(BCStyle.ST, in.nextLine());
						System.out.println("C:");
						nameBuilder.addRDN(BCStyle.C, in.nextLine());
						System.out.println("E:");
						String email = in.nextLine();
						String ePattern = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*"
								+ "@[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";
						java.util.regex.Pattern p = java.util.regex.Pattern.compile(ePattern);
				        java.util.regex.Matcher m = p.matcher(email);
				        if (!m.matches())
				        	throw new Exception("Nije uneta adekvatna email adresa!");
						nameBuilder.addRDN(BCStyle.E, email);
						
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
							System.out.println("Broj imena?");
							int num = in.nextInt();
							GeneralName[] gn = new GeneralName[num];
							for (int i = 0; i < num; i++)
							{
								System.out.println("Tip alternativnog imena"
										+ "	[0 - email, 1 - dNSName, 2 - uniformResourceIdentifier, 3 - iPAddress]:");
								int altNameType = in.nextInt();
								
								switch(altNameType)
								{
									case 0:	// email
									{
										System.out.println("E-mail:");
										in.nextLine();
										String value = in.nextLine();
										m = p.matcher(value);
								        if (!m.matches())
								        	throw new Exception("Nije uneta adekvatna email adresa!");
										DERGeneralString dgs = new DERGeneralString(value);
										gn[i] = new GeneralName(GeneralName.rfc822Name, dgs);
									} break;
									case 1: // DNS
									{
										System.out.println("DNS:");
										in.nextLine();
										gn[i] = new GeneralName(GeneralName.dNSName, in.nextLine());
									} break;
									case 2:	// URI
									{
										System.out.println("Ime seme:");
										in.nextLine();
										String sema = in.nextLine();
										System.out.println("Deo specifican za semu:");
										gn[i] = new GeneralName(GeneralName.uniformResourceIdentifier, sema + ":" + in.nextLine());
									} break;
									case 3:
									{
										System.out.println("Adresa:");
										in.nextLine();
										String adresa = in.nextLine();
										if (!IPAddress.isValid(adresa))
											throw new Exception("Nije validna IP-adresa!");
										InetAddress ip = InetAddress.getByName(adresa);
										gn[i] = new GeneralName(GeneralName.iPAddress, new DEROctetString(ip.getAddress()));
									} break;
									default: break;
								}
							}
							
							certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.18"),
							        critical,
							        new GeneralNames(gn));
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
						
						System.out.println("Unesite ime pod kojim zelite da sacuvate par kljuceva:");
						in.nextLine();
						String defaultalias = in.nextLine();
						
						java.security.cert.X509Certificate cert = new JcaX509CertificateConverter().
								setProvider("BC").getCertificate(certBuilder.build(
								new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey)));
						keystore.setKeyEntry(defaultalias, privKey, keypass.toCharArray(), 
								new java.security.cert.X509Certificate[]{cert});
						FileOutputStream outStream = new FileOutputStream ("keys");
						keystore.store(outStream, keypass.toCharArray());
						outStream.close();
							
	//						cert.verify(pubKey);
	//						System.out.println(privKey.toString());
						
					}
					break;
					case 2:
					{
						try {
							System.out.println("UVOZ - 0 / IZVOZ - 1");
							int odabrano = in.nextInt();
							if (odabrano == 0)
							{
								System.out.println("Unesite ime pod kojim ste sacuvali par kljuceva:");
								in.nextLine();
								String alias = in.nextLine();
								System.out.println("Unesite sifru:");
								String pass = in.nextLine();
								
								byte[] key = pass.getBytes("UTF-8");
						        MessageDigest sha = MessageDigest.getInstance("SHA-1");
						        key = sha.digest(key);
						        key = Arrays.copyOf(key, 16); // use only first 128 bit
						        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
						        
						        Cipher c = Cipher.getInstance("AES");
						        c.init(Cipher.DECRYPT_MODE, secretKeySpec);
								KeyStore ks = KeyStore.getInstance("pkcs12");
							    
						        File inputFile = new File(alias + ".p12");
						        FileInputStream inputStream = new FileInputStream(inputFile);
						        byte[] inputBytes = new byte[(int) inputFile.length()];
					            inputStream.read(inputBytes);
					            byte[] outputBytes = c.doFinal(inputBytes);
					            inputStream.close();
					            InputStream inStream = new ByteArrayInputStream(outputBytes); 
					            ks.load(inStream, pass.toCharArray());
					            
								PrivateKey privKey = (PrivateKey) ks.getKey(alias, pass.toCharArray());
								java.security.cert.Certificate certif = ks.getCertificate(alias);
								System.out.println(certif.toString());
//								System.out.println("Unesite alias:");
//								alias = in.nextLine();
//								keystore.setKeyEntry(alias, privKey, pass.toCharArray(), 
//										new java.security.cert.X509Certificate[]{(X509Certificate)certif});
//								FileOutputStream outs = new FileOutputStream("keys");
//								keystore.store(outs, keypass.toCharArray());
					            inStream.close();
							}
							else if (odabrano == 1)
							{
								Enumeration<String> enumeration = keystore.aliases();
								int i = 1;
								System.out.println("Aliasi postojecih kljuceva u keystore-u:");
						        while(enumeration.hasMoreElements()) {
						            String alias = (String)enumeration.nextElement();
						            System.out.println(i + ". " + alias);
						            i++;
						        }
						        System.out.println("Unesite alias:");
						        in.nextLine();
						        String alias = in.nextLine();
						        System.out.println("Unesite naziv fajla:");
						        String filename = in.nextLine();
						        System.out.println("Unesite sifru:");
						        String keypasstemp = in.nextLine();
						        
						        byte[] key = keypasstemp.getBytes("UTF-8");
						        MessageDigest sha = MessageDigest.getInstance("SHA-1");
						        key = sha.digest(key);
						        key = Arrays.copyOf(key, 16); // use only first 128 bit
						        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
						        
						        Cipher c = Cipher.getInstance("AES");
						        c.init(Cipher.ENCRYPT_MODE, secretKeySpec);
						        
						        FileOutputStream outStream = new FileOutputStream (filename + ".p12");
						        KeyStore keystore1 = KeyStore.getInstance("pkcs12");
						        keystore1.load(null, keypasstemp.toCharArray());
						        PrivateKey privKey = (PrivateKey) keystore.getKey(alias, keypass.toCharArray());
								java.security.cert.Certificate certif = keystore.getCertificate(alias);
						        keystore1.setKeyEntry(alias, privKey, keypasstemp.toCharArray(), 
										new java.security.cert.X509Certificate[]{(X509Certificate)certif});
						        keystore1.store(outStream, keypasstemp.toCharArray());
						        outStream.close();
						        
						        File inputFile = new File(filename + ".p12");
						        FileInputStream inputStream = new FileInputStream(inputFile);
						        byte[] inputBytes = new byte[(int) inputFile.length()];
					            inputStream.read(inputBytes);
					            byte[] outputBytes = c.doFinal(inputBytes);
					            FileOutputStream outputStream = new FileOutputStream(inputFile);
					            outputStream.write(outputBytes);
					             
					            inputStream.close();
					            outputStream.close();
							}
							else
								System.out.println("Uneta je pogresna opcija.");
							
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
					break;
					case 3:
					{
						try {
	//						KeyStore keystore = KeyStore.getInstance("pkcs12");
	//						String keypass = "password";
							FileInputStream inStream = new FileInputStream("mykeystore.p12");
						    keystore.load(inStream, keypass.toCharArray());
						    inStream.close();
						    String defaultalias = "keystore";
						    java.security.cert.Certificate certif = keystore.getCertificate(defaultalias);
						    
						    keypass = "CApassword";
						    FileInputStream inStreamCA = new FileInputStream("CA.p12");
						    keystore.load(inStreamCA, keypass.toCharArray());
						    inStreamCA.close();
						    PrivateKey CAPrivateKey = (PrivateKey) keystore.getKey("CA", keypass.toCharArray());
						    		
							java.security.cert.Certificate certifCA = keystore.getCertificate("CA");
							
							ContentSigner signGen = new JcaContentSignerBuilder("SHA1withRSA").build(CAPrivateKey);
							
							PKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(
									X500Name.getInstance(((X509Certificate)certif).getSubjectX500Principal().getEncoded()),
											certif.getPublicKey());
							PKCS10CertificationRequest csr = builder.build(signGen);
							
							// ISPIS CSR
							PemObject pemObject = new PemObject("CERTIFICATE REQUEST", csr.getEncoded());
							StringWriter str = new StringWriter();
							JcaPEMWriter pw = new JcaPEMWriter(str);
							pw.writeObject(pemObject);
							pw.close();
							str.close();
							System.out.println(str);
							
							// PRIKAZ DETALJA SERTIFIKATA
							
							X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
									((X509Certificate)certifCA).getIssuerX500Principal(),
									((X509Certificate)certif).getSerialNumber(),
									((X509Certificate)certif).getNotBefore(), ((X509Certificate)certif).getNotAfter(),
									((X509Certificate)certif).getSubjectX500Principal(), certif.getPublicKey());
							
							Integer pathLenConstraint = ((X509Certificate)certif).getBasicConstraints();
							boolean isCritical = false;
							if (((X509Certificate)certif).getCriticalExtensionOIDs().contains("2.5.29.19"))
							{
								isCritical = true;
							}
							if(pathLenConstraint == Integer.MAX_VALUE)
							{
								certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"),
										isCritical,
								        new BasicConstraints(true));
							}
							else if (pathLenConstraint > -1)
							{
								certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"),
										isCritical,
								        new BasicConstraints(pathLenConstraint));
							}
							
							boolean[] keyUsage = ((X509Certificate)certif).getKeyUsage();
							if (keyUsage != null)
							{
								int keyUsageInt = 0;
								for (int i = 0; i < 9; i++)
								{
									if (keyUsage[i])
										keyUsageInt |= (1 << i);
								}
								certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.15"),
										true,
								        new KeyUsage(keyUsageInt));
							}
							
							if (((X509Certificate)certif).getIssuerAlternativeNames() != null)
							{
								 Iterator it = ((X509Certificate)certif).getIssuerAlternativeNames().iterator();
								 GeneralName[] gn = new GeneralName[((X509Certificate)certif).getIssuerAlternativeNames().size()];
								 int i = 0;
								 while (it.hasNext())
								 {
									 gn[i++] = GeneralName.getInstance(it.next());
								 }
								 certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.18"),
									        false,
									        new GeneralNames(gn));
							}
								        
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
					break;
					case 4:
					{
						try {
//							java.security.cert.Certificate certif = importCertificate("keystore", "password", "mykeystore.p12");
//							 File file = new File("encodedcert.cer");
//							 byte[] buf = certif.getEncoded();
//							 
//							 FileOutputStream os = new FileOutputStream(file);
//							 os.write(buf);
//							 
//							 Writer wr = new OutputStreamWriter(os, Charset.forName("UTF-8"));
//							 wr.write(Base64.getEncoder().withoutPadding().encodeToString(buf));
//							 wr.flush();
//							 os.close();
						} catch (Exception e) {
							e.printStackTrace();
						}
					}
					break;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		in.close();
	}

}
