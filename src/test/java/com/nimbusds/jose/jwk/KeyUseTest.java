/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package com.nimbusds.jose.jwk;


import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Date;

import junit.framework.TestCase;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.StandardCharset;
import com.nimbusds.jose.util.X509CertUtils;


/**
 * Tests the key use enumeration.
 *
 * @author Vladimir Dzhuvinov
 * @version 2022-02-07
 */
public class KeyUseTest extends TestCase {


	public void testConstantIdentifiers() {

		assertEquals("sig", KeyUse.SIGNATURE.identifier());
		assertEquals("sig", KeyUse.SIGNATURE.getValue());
		assertEquals("sig", KeyUse.SIGNATURE.toString());

		assertEquals(HeaderParameterNames.ENCRYPTION_ALGORITHM, KeyUse.ENCRYPTION.identifier());
		assertEquals(HeaderParameterNames.ENCRYPTION_ALGORITHM, KeyUse.ENCRYPTION.getValue());
		assertEquals(HeaderParameterNames.ENCRYPTION_ALGORITHM, KeyUse.ENCRYPTION.toString());
	}
	
	
	public void testCustomIdentifier()
		throws ParseException {
		
		KeyUse tls = new KeyUse("tls");
		assertEquals("tls", tls.identifier());
		assertEquals("tls", tls.getValue());
		assertEquals("tls", tls.toString());
		
		assertEquals("tls", KeyUse.parse("tls").identifier());
		assertEquals(tls, new KeyUse("tls"));
	}


	public void testParseConstants()
		throws ParseException {

		assertEquals(KeyUse.SIGNATURE, KeyUse.parse("sig"));
		assertEquals(KeyUse.ENCRYPTION, KeyUse.parse(HeaderParameterNames.ENCRYPTION_ALGORITHM));
	}


	public void testParseException_empty() {

		try {
			KeyUse.parse("");

			fail();

		} catch (ParseException e) {
			assertEquals("JWK use value must not be empty or blank", e.getMessage());
		}
	}


	public void testParseException_blank() {

		try {
			KeyUse.parse("  ");

			fail();

		} catch (ParseException e) {
			assertEquals("JWK use value must not be empty or blank", e.getMessage());
		}
	}


	public void testParseNull()
		throws ParseException {

		assertNull(KeyUse.parse(null));
	}
	
	
	public void testInferKeyUseFromX509Cert_RSAENC()
		throws IOException {
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/resources/sample-certs/ietf.crt"), StandardCharset.UTF_8);
		X509Certificate x509Cert = X509CertUtils.parse(pemEncodedCert);
		assertNull(KeyUse.from(x509Cert));
	}
	
	
	public void testInferKeyUseFromX509Cert_ECDH()
		throws IOException {
		
		String pemEncodedCert = IOUtils.readFileToString(new File("src/test/resources/sample-certs/wikipedia.crt"), StandardCharset.UTF_8);
		X509Certificate x509Cert = X509CertUtils.parse(pemEncodedCert);
		assertNull(KeyUse.from(x509Cert));
	}
	
	
	public void testKeyUseNotSpecified()
		throws Exception {
		
		// Generate self-signed certificate
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		X500Name issuer = new X500Name("cn=c2id");
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000L);
		Date exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
		X500Name subject = new X500Name("cn=c2id");
		JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
			issuer,
			serialNumber,
			nbf,
			exp,
			subject,
			keyPair.getPublic()
		);
		
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(keyPair.getPrivate()));
		X509Certificate cert = X509CertUtils.parse(certHolder.getEncoded());
		
		assertNull(KeyUse.from(cert));
	}
}
