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


import java.net.URI;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.text.ParseException;
import java.util.*;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotEquals;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import junit.framework.TestCase;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.StandardCharset;
import com.nimbusds.jwt.util.DateUtils;


/**
 * Tests the Octet Sequence JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version 2024-10-31
 */
public class OctetSequenceKeyTest extends TestCase {
	
	
	private static final Date EXP = DateUtils.fromSecondsSinceEpoch(13_000_000L);
	private static final Date NBF = DateUtils.fromSecondsSinceEpoch(12_000_000L);
	private static final Date IAT = DateUtils.fromSecondsSinceEpoch(11_000_000L);
	private static final KeyRevocation KEY_REVOCATION = new KeyRevocation(DateUtils.fromSecondsSinceEpoch(12_500_000L), KeyRevocation.Reason.COMPROMISED);


	public void testConstructorAndSerialization()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5t256 = new Base64URL("abc256");
		List<Base64> x5c = SampleCertificates.SAMPLE_X5C_RSA;

		Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

		OctetSequenceKey key = new OctetSequenceKey(k, null, ops, JWSAlgorithm.HS256, "1", x5u, x5t, x5t256, x5c, EXP, NBF, IAT, KEY_REVOCATION, keyStore);

		assertTrue(key instanceof SecretJWK);

		assertEquals(KeyType.OCT, key.getKeyType());
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertEquals(EXP, key.getExpirationTime());
		assertEquals(NBF, key.getNotBeforeTime());
		assertEquals(IAT, key.getIssueTime());
		assertEquals(KEY_REVOCATION, key.getKeyRevocation());
		assertEquals(keyStore, key.getKeyStore());

		assertEquals(k, key.getKeyValue());

		byte[] keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {
			assertEquals(keyBytes[i], key.toByteArray()[i]);
		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());

		String jwkString = JSONObjectUtils.toJSONString( key.toJSONObject());

		key = OctetSequenceKey.parse(jwkString);

		assertEquals(KeyType.OCT, key.getKeyType());
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertEquals(EXP, key.getExpirationTime());
		assertEquals(NBF, key.getNotBeforeTime());
		assertEquals(IAT, key.getIssueTime());
		assertEquals(KEY_REVOCATION, key.getKeyRevocation());
		assertNull(key.getKeyStore());

		assertEquals(k, key.getKeyValue());

		keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {

			assertEquals(keyBytes[i], key.toByteArray()[i]);

		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());
	}


	public void testConstructorAndSerialization_deprecated()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5t256 = new Base64URL("abc256");
		List<Base64> x5c = SampleCertificates.SAMPLE_X5C_RSA;

		Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

		OctetSequenceKey key = new OctetSequenceKey(k, null, ops, JWSAlgorithm.HS256, "1", x5u, x5t, x5t256, x5c, keyStore);

		assertTrue(key instanceof SecretJWK);

		assertEquals(KeyType.OCT, key.getKeyType());
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertNull(key.getExpirationTime());
		assertNull(key.getNotBeforeTime());
		assertNull(key.getIssueTime());
		assertNull(key.getKeyRevocation());
		assertEquals(keyStore, key.getKeyStore());

		assertEquals(k, key.getKeyValue());

		byte[] keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {
			assertEquals(keyBytes[i], key.toByteArray()[i]);
		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());

		String jwkString = JSONObjectUtils.toJSONString( key.toJSONObject());

		key = OctetSequenceKey.parse(jwkString);

		assertEquals(KeyType.OCT, key.getKeyType());
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertNull(key.getExpirationTime());
		assertNull(key.getNotBeforeTime());
		assertNull(key.getIssueTime());
		assertNull(key.getKeyRevocation());
		assertNull(key.getKeyStore());

		assertEquals(k, key.getKeyValue());

		keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {

			assertEquals(keyBytes[i], key.toByteArray()[i]);

		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());
	}


	public void testAltConstructorAndSerialization()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5t256 = new Base64URL("abc256");
		List<Base64> x5c = SampleCertificates.SAMPLE_X5C_RSA;

		OctetSequenceKey key = new OctetSequenceKey(k, KeyUse.SIGNATURE, null, JWSAlgorithm.HS256, "1", x5u, x5t, x5t256, x5c,  EXP, NBF, IAT, KEY_REVOCATION, null);

		assertEquals(KeyType.OCT, key.getKeyType());
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertEquals(EXP, key.getExpirationTime());
		assertEquals(NBF, key.getNotBeforeTime());
		assertEquals(IAT, key.getIssueTime());
		assertEquals(KEY_REVOCATION, key.getKeyRevocation());
		assertNull(key.getKeyStore());

		assertEquals(k, key.getKeyValue());

		byte[] keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {
			assertEquals(keyBytes[i], key.toByteArray()[i]);
		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());

		String jwkString = JSONObjectUtils.toJSONString( key.toJSONObject());

		key = OctetSequenceKey.parse(jwkString);

		assertEquals(KeyType.OCT, key.getKeyType());
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertEquals(EXP, key.getExpirationTime());
		assertEquals(NBF, key.getNotBeforeTime());
		assertEquals(IAT, key.getIssueTime());
		assertEquals(KEY_REVOCATION, key.getKeyRevocation());

		assertEquals(k, key.getKeyValue());

		keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {

			assertEquals(keyBytes[i], key.toByteArray()[i]);

		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());
	}


	public void testAltConstructorAndSerialization_deprecated()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		Base64URL x5t256 = new Base64URL("abc256");
		List<Base64> x5c = SampleCertificates.SAMPLE_X5C_RSA;

		OctetSequenceKey key = new OctetSequenceKey(k, KeyUse.SIGNATURE, null, JWSAlgorithm.HS256, "1", x5u, x5t, x5t256, x5c, null);

		assertEquals(KeyType.OCT, key.getKeyType());
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertNull(key.getExpirationTime());
		assertNull(key.getNotBeforeTime());
		assertNull(key.getIssueTime());
		assertNull(key.getKeyRevocation());
		assertNull(key.getKeyStore());

		assertEquals(k, key.getKeyValue());

		byte[] keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {
			assertEquals(keyBytes[i], key.toByteArray()[i]);
		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());

		String jwkString = JSONObjectUtils.toJSONString( key.toJSONObject());

		key = OctetSequenceKey.parse(jwkString);

		assertEquals(KeyType.OCT, key.getKeyType());
		assertEquals(KeyUse.SIGNATURE, key.getKeyUse());
		assertNull(key.getKeyOperations());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5t256.toString(), key.getX509CertSHA256Thumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertNull(key.getExpirationTime());
		assertNull(key.getNotBeforeTime());
		assertNull(key.getIssueTime());
		assertNull(key.getKeyRevocation());

		assertEquals(k, key.getKeyValue());

		keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {

			assertEquals(keyBytes[i], key.toByteArray()[i]);

		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());
	}


	public void testKeyUseConsistentWithOps() {

		KeyUse use = KeyUse.SIGNATURE;
		
		Set<KeyOperation> ops = new HashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

		JWK jwk = new OctetSequenceKey(new Base64URL("GawgguFyGrWKav7AX4VKUg"), use, ops, null, null, null, null, null, null, null);
		assertEquals(use, jwk.getKeyUse());
		assertEquals(ops, jwk.getKeyOperations());
	}
	
	
	public void testRejectKeyUseNotConsistentWithOps() {
		
		try {
			new OctetSequenceKey.Builder(new Base64URL("GawgguFyGrWKav7AX4VKUg"))
				.keyUse(KeyUse.SIGNATURE)
				.keyOperations(Collections.singleton(KeyOperation.ENCRYPT))
				.build();
			fail();
		} catch (IllegalStateException e) {
			assertEquals("The key use \"use\" and key options \"key_ops\" parameters are not consistent, see RFC 7517, section 4.3", e.getMessage());
		}
	}


	public void testBuilder()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = SampleCertificates.SAMPLE_X5C_RSA;

		Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

		OctetSequenceKey key = new OctetSequenceKey.Builder(k)
			.keyOperations(ops)
			.algorithm(JWSAlgorithm.HS256)
			.keyID("1")
			.x509CertURL(x5u)
			.x509CertThumbprint(x5t)
			.x509CertChain(x5c)
			.expirationTime(EXP)
			.notBeforeTime(NBF)
			.issueTime(IAT)
			.keyRevocation(KEY_REVOCATION)
			.keyStore(keyStore)
			.build();

		assertEquals(KeyType.OCT, key.getKeyType());
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertEquals(EXP, key.getExpirationTime());
		assertEquals(NBF, key.getNotBeforeTime());
		assertEquals(IAT, key.getIssueTime());
		assertEquals(KEY_REVOCATION, key.getKeyRevocation());
		assertEquals(keyStore, key.getKeyStore());

		assertEquals(k, key.getKeyValue());

		byte[] keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {
			assertEquals(keyBytes[i], key.toByteArray()[i]);
		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());


		String jwkString = JSONObjectUtils.toJSONString( key.toJSONObject());

		key = OctetSequenceKey.parse(jwkString);


		assertEquals(KeyType.OCT, key.getKeyType());
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertEquals(EXP, key.getExpirationTime());
		assertEquals(NBF, key.getNotBeforeTime());
		assertEquals(IAT, key.getIssueTime());
		assertEquals(KEY_REVOCATION, key.getKeyRevocation());
		assertNull(key.getKeyStore());

		assertEquals(k, key.getKeyValue());

		keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {
			assertEquals(keyBytes[i], key.toByteArray()[i]);
		}

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());
	}


	public void testCopyBuilder()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = SampleCertificates.SAMPLE_X5C_RSA;

		Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));
		
		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

		OctetSequenceKey key = new OctetSequenceKey.Builder(k)
			.keyOperations(ops)
			.algorithm(JWSAlgorithm.HS256)
			.keyID("1")
			.x509CertURL(x5u)
			.x509CertThumbprint(x5t)
			.x509CertChain(x5c)
			.expirationTime(EXP)
			.notBeforeTime(NBF)
			.issueTime(IAT)
			.keyRevocation(KEY_REVOCATION)
			.keyStore(keyStore)
			.build();
		
		// Copy
		key = new OctetSequenceKey.Builder(key).build();

		assertEquals(KeyType.OCT, key.getKeyType());
		assertNull(key.getKeyUse());
		assertTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, key.getKeyOperations().size());
		assertEquals(JWSAlgorithm.HS256, key.getAlgorithm());
		assertEquals("1", key.getKeyID());
		assertEquals(x5u.toString(), key.getX509CertURL().toString());
		assertEquals(x5t.toString(), key.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), key.getX509CertChain().size());
		assertEquals(EXP, key.getExpirationTime());
		assertEquals(NBF, key.getNotBeforeTime());
		assertEquals(IAT, key.getIssueTime());
		assertEquals(KEY_REVOCATION, key.getKeyRevocation());
		assertEquals(keyStore, key.getKeyStore());

		assertEquals(k, key.getKeyValue());

		assertNull(key.toPublicJWK());

		assertTrue(key.isPrivate());
	}


	public void testBuilderWithByteArray() {

		byte[] key = new byte[32];
		new SecureRandom().nextBytes(key);

		OctetSequenceKey oct = new OctetSequenceKey.Builder(key).build();

		assertEquals(Base64URL.encode(key), oct.getKeyValue());
	}


	public void testBuilderWithSecretKey() {

		byte[] key = new byte[32];
		new SecureRandom().nextBytes(key);

		OctetSequenceKey oct = new OctetSequenceKey.Builder(new SecretKeySpec(key, "MAC")).keyUse(KeyUse.SIGNATURE).build();

		SecretKey secretKey = oct.toSecretKey();
		assertArrayEquals(key, secretKey.getEncoded());
		assertEquals("NONE", secretKey.getAlgorithm());
	}


	public void testCookbookHMACKeyExample()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7c520#section-3.5
		
		String json ="{"+
			"\"kty\":\"oct\","+
			"\"kid\":\"018c0ae5-4d9b-471b-bfd6-eef314bc7037\","+
			"\"use\":\"sig\","+
			"\"k\":\"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\""+
			"}";

		OctetSequenceKey jwk = OctetSequenceKey.parse(json);

		assertEquals(KeyType.OCT, jwk.getKeyType());
		assertEquals("018c0ae5-4d9b-471b-bfd6-eef314bc7037", jwk.getKeyID());
		assertEquals(KeyUse.SIGNATURE, jwk.getKeyUse());

		assertEquals("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg", jwk.getKeyValue().toString());
	}


	public void testCookbookAESKeyExample()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7520#section-5.3.1

		String json ="{"+
			"\"kty\":\"oct\","+
			"\"kid\":\"77c7e2b8-6e13-45cf-8672-617b5b45243a\","+
			"\"use\":\"enc\","+
			"\"alg\":\"A128GCM\","+
			"\"k\":\"XctOhJAkA-pD9Lh7ZgW_2A\""+
			"}";

		OctetSequenceKey jwk = OctetSequenceKey.parse(json);

		assertEquals(KeyType.OCT, jwk.getKeyType());
		assertEquals("77c7e2b8-6e13-45cf-8672-617b5b45243a", jwk.getKeyID());
		assertEquals(KeyUse.ENCRYPTION, jwk.getKeyUse());
		assertEquals(EncryptionMethod.A128GCM, jwk.getAlgorithm());

		assertEquals("XctOhJAkA-pD9Lh7ZgW_2A", jwk.getKeyValue().toString());
	}


	public void testToSecretKey() {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");

		OctetSequenceKey jwk = new OctetSequenceKey.Builder(k).build();
		
		assertArrayEquals(k.decode(), jwk.toSecretKey().getEncoded());
		assertEquals("NONE", jwk.toSecretKey().getAlgorithm());
	}


	public void testToSecretKeyWithAlg() {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");

		OctetSequenceKey jwk = new OctetSequenceKey.Builder(k).build();
		
		assertArrayEquals(k.decode(), jwk.toSecretKey("AES").getEncoded());
		assertEquals("AES", jwk.toSecretKey("AES").getAlgorithm());
	}


	public void testThumbprint()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");

		OctetSequenceKey jwk = new OctetSequenceKey.Builder(k).build();

		Base64URL thumbprint = jwk.computeThumbprint();

		assertEquals(256 / 8, thumbprint.decode().length);

		String orderedJSON = "{\"k\":\"GawgguFyGrWKav7AX4VKUg\",\"kty\":\"oct\"}";

		Base64URL expected = Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(orderedJSON.getBytes(StandardCharset.UTF_8)));

		assertEquals(expected, thumbprint);
	}


	public void testThumbprintSHA1()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");

		OctetSequenceKey jwk = new OctetSequenceKey.Builder(k).build();

		Base64URL thumbprint = jwk.computeThumbprint("SHA-1");

		assertEquals(160 / 8, thumbprint.decode().length);
	}


	public void testThumbprintAsKeyID()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");

		OctetSequenceKey jwk = new OctetSequenceKey.Builder(k).keyIDFromThumbprint().build();

		Base64URL thumbprint = new Base64URL(jwk.getKeyID());

		assertEquals(256 / 8, thumbprint.decode().length);

		String orderedJSON = JSONObjectUtils.toJSONString(jwk.getRequiredParams());

		Base64URL expected = Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(orderedJSON.getBytes(StandardCharset.UTF_8)));

		assertEquals(expected, thumbprint);
	}


	public void testThumbprintSHA1AsKeyID()
		throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");

		OctetSequenceKey jwk = new OctetSequenceKey.Builder(k).keyIDFromThumbprint("SHA-1").build();

		Base64URL thumbprint = new Base64URL(jwk.getKeyID());

		assertEquals(160 / 8, thumbprint.decode().length);
	}


	// See https://mailarchive.ietf.org/arch/msg/jose/gS-nOfqgV1n17DFUd6w_yBEf0sU
	public void testJose4jVector()
		throws Exception {

		String json = "{\"kty\":\"oct\"," +
			"\"k\":\"ZW8Eg8TiwoT2YamLJfC2leYpLgLmUAh_PcMHqRzBnMg\"}";

		OctetSequenceKey jwk = OctetSequenceKey.parse(json);

		assertEquals("7WWD36NF4WCpPaYtK47mM4o0a5CCeOt01JXSuMayv5g", jwk.computeThumbprint().toString());
	}


	public void testSize() {

		byte[] keyMaterial = new byte[24];
		new SecureRandom().nextBytes(keyMaterial);
		assertEquals(24 * 8, new OctetSequenceKey.Builder(keyMaterial).build().size());
	}
	
	
	public void testLoadFromKeyStore()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		gen.init(128);
		SecretKey secretKey = gen.generateKey();
		
		keyStore.setEntry("1", new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection("1234".toCharArray()));
		
		OctetSequenceKey octJWK = OctetSequenceKey.load(keyStore, "1", "1234".toCharArray());
		assertNotNull(octJWK);
		assertEquals("1", octJWK.getKeyID());
		assertNull(octJWK.getExpirationTime());
		assertNull(octJWK.getNotBeforeTime());
		assertNull(octJWK.getIssueTime());
		assertArrayEquals(secretKey.getEncoded(), octJWK.toByteArray());
		assertEquals(keyStore, octJWK.getKeyStore());
	}
	
	
	public void testLoadFromKeyStore_emptyPassword()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		gen.init(128);
		SecretKey secretKey = gen.generateKey();
		
		keyStore.setEntry("1", new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection("".toCharArray()));
		
		OctetSequenceKey octJWK = OctetSequenceKey.load(keyStore, "1", "".toCharArray());
		assertNotNull(octJWK);
		assertEquals("1", octJWK.getKeyID());
		assertNull(octJWK.getExpirationTime());
		assertNull(octJWK.getNotBeforeTime());
		assertNull(octJWK.getIssueTime());
		assertArrayEquals(secretKey.getEncoded(), octJWK.toByteArray());
		assertEquals(keyStore, octJWK.getKeyStore());
	}
	
	
	public void testLoadFromKeyStore_notFound()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		assertNull(OctetSequenceKey.load(keyStore, "1", "1234".toCharArray()));
	}
	
	
	public void testLoadFromKeyStore_badPin()
		throws Exception {
		
		KeyStore keyStore = KeyStore.getInstance("JCEKS");
		
		char[] password = "secret".toCharArray();
		keyStore.load(null, password);
		
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		gen.init(128);
		SecretKey secretKey = gen.generateKey();
		
		keyStore.setEntry("1", new KeyStore.SecretKeyEntry(secretKey), new KeyStore.PasswordProtection("1234".toCharArray()));
		
		try {
			OctetSequenceKey.load(keyStore, "1", "badpin".toCharArray());
			fail();
		} catch (Exception e) {
			assertTrue("Expected exception to contain \"Couldn't retrieve secret key (bad pin?)\", but was: " + e.getMessage(),
					e.getMessage().contains("Couldn't retrieve secret key (bad pin?)"));
			assertTrue(e.getCause() instanceof UnrecoverableKeyException);
		}
	}

	public void testEqualsSuccess()
			throws Exception {

		//Given
		String json ="{"+
				"\"kty\":\"oct\","+
				"\"kid\":\"018c0ae5-4d9b-471b-bfd6-eef314bc7037\","+
				"\"use\":\"sig\","+
				"\"k\":\"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\""+
				"}";

		OctetSequenceKey jwkA = OctetSequenceKey.parse(json);
		OctetSequenceKey jwkB = OctetSequenceKey.parse(json);

		//When

		//Then
		assertEquals(jwkA, jwkB);
	}

	public void testEqualsFailure()
			throws Exception {

		//Given
		String jsonA ="{"+
				"\"kty\":\"oct\","+
				"\"kid\":\"018c0ae5-4d9b-471b-bfd6-eef314bc7037\","+
				"\"use\":\"sig\","+
				"\"k\":\"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\""+
				"}";
		OctetSequenceKey jwkA = OctetSequenceKey.parse(jsonA);

		String jsonB ="{"+
				"\"kty\":\"oct\","+
				"\"kid\":\"018c0ae5-4d9b-471b-bfd6-eef314bc7037\","+
				"\"use\":\"sig\","+
				"\"k\":\"werewrwerewr\""+
				"}";
		OctetSequenceKey jwkB = OctetSequenceKey.parse(jsonB);

		//When

		//Then
		assertNotEquals(jwkA, jwkB);
	}
	
	
	public void testParse_fromEmptyJSONObject() {
		
		try {
			OctetSequenceKey.parse(JSONObjectUtils.newJSONObject());
			fail();
		} catch (ParseException e) {
			assertEquals("The key type to parse must not be null", e.getMessage());
		}
	}
	
	
	public void testParse_missingKty() {
		
		Map<String, Object> jsonObject =JSONObjectUtils.newJSONObject();
		jsonObject.put(JWKParameterNames.OCT_KEY_VALUE, "werewrwerewr");
		
		try {
			OctetSequenceKey.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("The key type to parse must not be null", e.getMessage());
		}
	}
	
	
	public void testParse_missingK() {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(JWKParameterNames.KEY_TYPE, "oct");
		
		try {
			OctetSequenceKey.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("The key value must not be null", e.getMessage());
		}
	}
	
	
	public void testParse_nullK() {
		
		Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
		jsonObject.put(JWKParameterNames.KEY_TYPE, "oct");
		jsonObject.put(JWKParameterNames.OCT_KEY_VALUE, null);
		
		try {
			OctetSequenceKey.parse(jsonObject);
			fail();
		} catch (ParseException e) {
			assertEquals("The key value must not be null", e.getMessage());
		}
	}


	public void testToRevokedJWK() throws JOSEException {

		OctetSequenceKey jwk = new OctetSequenceKeyGenerator(128).generate();

		jwk = jwk.toRevokedJWK(KEY_REVOCATION);

		assertEquals(KEY_REVOCATION, jwk.getKeyRevocation());
	}


	public void testToRevokedJWK_fullySpecced() throws Exception {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		URI x5u = new URI("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = SampleCertificates.SAMPLE_X5C_RSA;

		Set<KeyOperation> ops = new LinkedHashSet<>(Arrays.asList(KeyOperation.SIGN, KeyOperation.VERIFY));

		KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

		OctetSequenceKey jwk = new OctetSequenceKey.Builder(k)
			.keyOperations(ops)
			.algorithm(JWSAlgorithm.HS256)
			.keyID("1")
			.x509CertURL(x5u)
			.x509CertThumbprint(x5t)
			.x509CertChain(x5c)
			.expirationTime(EXP)
			.notBeforeTime(NBF)
			.issueTime(IAT)
			.keyStore(keyStore)
			.build();

		jwk = jwk.toRevokedJWK(KEY_REVOCATION);

		assertEquals(KeyType.OCT, jwk.getKeyType());
		assertNull(jwk.getKeyUse());
		assertTrue(jwk.getKeyOperations().contains(KeyOperation.SIGN));
		assertTrue(jwk.getKeyOperations().contains(KeyOperation.VERIFY));
		assertEquals(2, jwk.getKeyOperations().size());
		assertEquals(JWSAlgorithm.HS256, jwk.getAlgorithm());
		assertEquals("1", jwk.getKeyID());
		assertEquals(x5u.toString(), jwk.getX509CertURL().toString());
		assertEquals(x5t.toString(), jwk.getX509CertThumbprint().toString());
		assertEquals(x5c.size(), jwk.getX509CertChain().size());
		assertEquals(EXP, jwk.getExpirationTime());
		assertEquals(NBF, jwk.getNotBeforeTime());
		assertEquals(IAT, jwk.getIssueTime());
		assertEquals(KEY_REVOCATION, jwk.getKeyRevocation());
		assertEquals(keyStore, jwk.getKeyStore());

		assertEquals(k, jwk.getKeyValue());

		assertNull(jwk.toPublicJWK());

		assertTrue(jwk.isPrivate());
	}


	public void testToRevokedJWK_alreadyRevoked() throws JOSEException {

		OctetSequenceKey jwk = new OctetSequenceKeyGenerator(128).generate();

		jwk = new OctetSequenceKey.Builder(jwk)
			.keyRevocation(KEY_REVOCATION)
			.build();

		assertEquals(KEY_REVOCATION, jwk.getKeyRevocation());

		try {
			jwk.toRevokedJWK(KEY_REVOCATION);
			fail();
		} catch (IllegalStateException e) {
			assertEquals("Already revoked", e.getMessage());
		}
	}


	public void testToRevokedJWK_nullKeyRevocation() throws JOSEException {

		OctetSequenceKey jwk = new OctetSequenceKeyGenerator(128).generate();

		try {
			jwk.toRevokedJWK(null);
			fail();
		} catch (NullPointerException e) {
			assertNull(e.getMessage());
		}
	}
}
