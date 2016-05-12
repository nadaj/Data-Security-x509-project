package main;

import java.security.*;
import java.security.cert.CertificateFactory;
import java.util.Scanner;


public class Main {

	public static void main(String[] args) {
		int option = 0;
		Scanner in = new Scanner(System.in);
		
		while (true)
		{
			System.out.println("\nOdaberite funkcionalnost:");
			System.out.println("1. Generisanje novog para kljuceva");
			System.out.println("-------------------------------------------1" +
					"");
			option = in.nextInt();
			switch(option)
			{
				case 1: {
					try {
						System.out.println("\nVelicina kljuca:");
						System.out.println("Verzija sertifikata:");
						System.out.println("Period vazenja:");
						System.out.println("Serijski broj:");
						System.out.println("Informacije o korisniku (CN, OU, O, L, ST, C, E):");
						System.out.println("[Opciono ekstenzije]: KRITICNE ILI NE");
						System.out.println("Osnovna ogranicenja: ");
						System.out.println("Alternativna imena izdavaoca sertifikata: ");
						System.out.println("Koriscenje kljuca: ");
						CertificateFactory cf = CertificateFactory.getInstance("X.509");
						
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		}
	}

}
