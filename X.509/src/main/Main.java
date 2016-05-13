package main;

import java.math.BigInteger;
import java.security.*;
import java.text.SimpleDateFormat;
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
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Main {

	public static void main(String[] args) {
		int option = 0;
		Scanner in = new Scanner(System.in);
		
		while (true)
		{
			System.out.println("\nOdaberite funkcionalnost:");
			System.out.println("0. Kraj");
			System.out.println("1. Generisanje novog para kljuceva za sertifikat");
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
						
						System.out.println("Period vazenja - OD (format dd-mm-yyyy):");
						String dateFrom = in.next();
						SimpleDateFormat dateFormat = new SimpleDateFormat("dd-MM-yyyy");
						Date date1 = dateFormat.parse(dateFrom);
						
						System.out.println("Period vazenja - DO (format dd-mm-yyyy):");
						String dateTo = in.next();
						Date date2 = dateFormat.parse(dateTo);
						if (date2.before(date1))
						{
							System.out.println("Nisu ispravni uneti datumi.");
						}
						
						System.out.println("Serijski broj:");
						BigInteger serialNumber = in.nextBigInteger();
						if (serialNumber.signum() == -1 || serialNumber.signum() == 0)
						{
							System.out.println("Serijski broj mora da bude pozitivan ceo broj.");
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
//						System.out.println("privateKey : " + privKey.toString());
//					    System.out.println("publicKey : " + pubKey.toString());
					    
					    
					    X500Name issuerName = nameBuilder.build();
					    X500Name subject = issuerName;
					    X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuerName, serialNumber,
					    		date1, date2, subject, pubKey);
					    
						// EKSTENZIJE : MORA BAR 1
						int selected = 0;
						System.out.println("Osnovna ogranicenja: \nPrisutno[0/1]:");
						int temp = in.nextInt();
						boolean critical;
						boolean cA = false;
						if (temp == 1)
						{
							selected++;
							System.out.println("Kriticno[true/false]:");
							critical = in.nextBoolean();
							System.out.println("cA[true/false]:");
							cA = in.nextBoolean();
							if (cA)
							{
								System.out.println("pathLenConstraint[-1-not present/vrednost]:");
								int pathLenConstraint = in.nextInt();
								if (pathLenConstraint < -1)
								{
									System.out.println("Osnovna ogranicenja: parametar pathLenConstraint mora biti ceo broj > 0.");
									break;
								}
								if (pathLenConstraint != -1)
									certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"),
								        critical,
								        new BasicConstraints(pathLenConstraint));
								else
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
							System.out.println("Kriticno[true/false]:");
							critical = in.nextBoolean();
							System.out.println("Tip alternativnog imena	[0 - otherName, 1 - rfc822, 2 - dNSName, 3 - x400Address"
									+ ", 4- directoryName, 5 - ediPartyName, 6 - uniformResourceIdentifier, 7 - iPAddress, 8 - registeredID :");
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
							System.out.println("Kriticno[true/false]:");
							critical = in.nextBoolean();
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
									keyUsageValue |= KeyUsage.keyCertSign;
								
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
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
				break;
			}
		}
	}

}
