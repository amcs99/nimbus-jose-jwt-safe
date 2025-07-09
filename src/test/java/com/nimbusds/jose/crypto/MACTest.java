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

package com.nimbusds.jose.crypto;


import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.impl.MACProvider;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.jwt.JWTClaimNames;
import junit.framework.TestCase;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.*;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotEquals;


/**
 * Tests HMAC JWS signing and verification. Uses test vectors from JWS spec.
 *
 * @author Vladimir Dzhuvinov
 * @version 2024-10-28
 */
public class MACTest extends TestCase {


	private static final byte[] sharedSecret = 

		{ (byte)   3, (byte)  35, (byte)  53, (byte)  75, (byte)  43, (byte)  15, (byte) 165, (byte) 188, 
		  (byte) 131, (byte) 126, (byte)   6, (byte) 101, (byte) 119, (byte) 123, (byte) 166, (byte) 143, 
		  (byte)  90, (byte) 179, (byte)  40, (byte) 230, (byte) 240, (byte)  84, (byte) 201, (byte)  40, 
		  (byte) 169, (byte)  15, (byte) 132, (byte) 178, (byte) 210, (byte)  80, (byte)  46, (byte) 191, 
		  (byte) 211, (byte) 251, (byte)  90, (byte) 146, (byte) 210, (byte)   6, (byte)  71, (byte) 239, 
		  (byte) 150, (byte) 138, (byte) 180, (byte) 195, (byte) 119, (byte)  98, (byte)  61, (byte)  34, 
		  (byte)  61, (byte)  46, (byte)  33, (byte) 114, (byte)   5, (byte)  46, (byte)  79, (byte)   8, 
		  (byte) 192, (byte) 205, (byte) 154, (byte) 245, (byte) 103, (byte) 208, (byte) 128, (byte) 163  };


	private static final Base64URL B64_HEADER = new Base64URL("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");


	private static final Payload PAYLOAD = new Payload(new Base64URL("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ"));


	private static final byte[] SIGNABLE = ("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
		"." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
		"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ").getBytes();


	private static final Base64URL B64_SIG = new Base64URL("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");


	public void testClassAlgorithmSupport() {

		assertEquals(3, MACProvider.SUPPORTED_ALGORITHMS.size());
		assertTrue(MACProvider.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.HS256));
		assertTrue(MACProvider.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.HS384));
		assertTrue(MACProvider.SUPPORTED_ALGORITHMS.contains(JWSAlgorithm.HS512));
	}


	public void testInstanceAlgorithmSupport()
		throws JOSEException {

		// 256-bit key
		final byte[] key256 = new byte[ByteUtils.byteLength(256)];
		new SecureRandom().nextBytes(key256);
		final SecretKey secretKey256 = new SecretKeySpec(key256, "HMACSHA256");

		for (MACSigner signer: Arrays.asList(new MACSigner(key256), new MACSigner(secretKey256))) {
			assertEquals(1, signer.supportedJWSAlgorithms().size());
			assertTrue(signer.supportedJWSAlgorithms().contains(JWSAlgorithm.HS256));
		}

		for (MACVerifier verifier: Arrays.asList(new MACVerifier(key256), new MACVerifier(secretKey256))) {
			assertEquals(1, verifier.supportedJWSAlgorithms().size());
			assertTrue(verifier.supportedJWSAlgorithms().contains(JWSAlgorithm.HS256));
		}

		// 384-bit key
		final byte[] key384 = new byte[ByteUtils.byteLength(384)];
		new SecureRandom().nextBytes(key384);
		final SecretKey secretKey384 = new SecretKeySpec(key384, "HMACSHA384");

		for (MACSigner signer: Arrays.asList(new MACSigner(key384), new MACSigner(secretKey384))) {
			assertEquals(2, signer.supportedJWSAlgorithms().size());
			assertTrue(signer.supportedJWSAlgorithms().contains(JWSAlgorithm.HS256));
			assertTrue(signer.supportedJWSAlgorithms().contains(JWSAlgorithm.HS384));
		}

		for (MACVerifier verifier: Arrays.asList(new MACVerifier(key384), new MACVerifier(secretKey384))) {
			assertEquals(2, verifier.supportedJWSAlgorithms().size());
			assertTrue(verifier.supportedJWSAlgorithms().contains(JWSAlgorithm.HS256));
			assertTrue(verifier.supportedJWSAlgorithms().contains(JWSAlgorithm.HS384));
		}

		// 512-bit key
		final byte[] key512 = new byte[ByteUtils.byteLength(512)];
		new SecureRandom().nextBytes(key512);
		final SecretKey secretKey512 = new SecretKeySpec(key512, "HMACSHA512");

		for (MACSigner signer: Arrays.asList(new MACSigner(key512), new MACSigner(secretKey512))) {
			assertEquals(3, signer.supportedJWSAlgorithms().size());
			assertTrue(signer.supportedJWSAlgorithms().contains(JWSAlgorithm.HS256));
			assertTrue(signer.supportedJWSAlgorithms().contains(JWSAlgorithm.HS384));
			assertTrue(signer.supportedJWSAlgorithms().contains(JWSAlgorithm.HS512));
		}

		for (MACVerifier verifier: Arrays.asList(new MACVerifier(key512), new MACVerifier(secretKey512))) {
			assertEquals(3, verifier.supportedJWSAlgorithms().size());
			assertTrue(verifier.supportedJWSAlgorithms().contains(JWSAlgorithm.HS256));
			assertTrue(verifier.supportedJWSAlgorithms().contains(JWSAlgorithm.HS384));
			assertTrue(verifier.supportedJWSAlgorithms().contains(JWSAlgorithm.HS512));
		}
	}


	public void testInstanceAlgorithmSupport_SecretKeyGetEncodedReturnsNull()
		throws JOSEException {

		byte[] key256 = new byte[ByteUtils.byteLength(256)];
		new SecureRandom().nextBytes(key256);
		SecretKey secretHSMKey = new SecretKey() {
			@Override
			public String getAlgorithm() {
				return "xxx";
			}

			@Override
			public String getFormat() {
				return null;
			}

			@Override
			public byte[] getEncoded() {
				return null;
			}
		};

		for (MACProvider macProvider: Arrays.asList(new MACSigner(secretHSMKey), new MACVerifier(secretHSMKey))) {

			assertEquals(3, macProvider.supportedJWSAlgorithms().size());
			assertTrue(macProvider.supportedJWSAlgorithms().contains(JWSAlgorithm.HS256));
			assertTrue(macProvider.supportedJWSAlgorithms().contains(JWSAlgorithm.HS384));
			assertTrue(macProvider.supportedJWSAlgorithms().contains(JWSAlgorithm.HS512));

			assertEquals(secretHSMKey, macProvider.getSecretKey());
			assertNull(macProvider.getSecret());
			assertNull(macProvider.getSecretString());
		}
	}


	public void testDetermineCompatibleAlgorithmForSecretSize() {

		Set<JWSAlgorithm> algs = MACProvider.getCompatibleAlgorithms(0);
		assertEquals(0, algs.size());

		algs = MACProvider.getCompatibleAlgorithms(128);
		assertEquals(0, algs.size());

		algs = MACProvider.getCompatibleAlgorithms(256);
		assertEquals(1, algs.size());
		assertTrue(algs.contains(JWSAlgorithm.HS256));

		algs = MACProvider.getCompatibleAlgorithms(384);
		assertEquals(2, algs.size());
		assertTrue(algs.contains(JWSAlgorithm.HS256));
		assertTrue(algs.contains(JWSAlgorithm.HS384));

		algs = MACProvider.getCompatibleAlgorithms(512);
		assertEquals(3, algs.size());
		assertTrue(algs.contains(JWSAlgorithm.HS256));
		assertTrue(algs.contains(JWSAlgorithm.HS384));
		assertTrue(algs.contains(JWSAlgorithm.HS512));

		algs = MACProvider.getCompatibleAlgorithms(1024);
		assertEquals(3, algs.size());
		assertTrue(algs.contains(JWSAlgorithm.HS256));
		assertTrue(algs.contains(JWSAlgorithm.HS384));
		assertTrue(algs.contains(JWSAlgorithm.HS512));
	}


	public void testSignAndVerifyWithVector()
		throws Exception {

		JWSHeader header = JWSHeader.parse(B64_HEADER);

		assertEquals("HS256 alg check", JWSAlgorithm.HS256, header.getAlgorithm());
		assertEquals("JWT type check", new JOSEObjectType("JWT"), header.getType());

		JWSObject jwsObject = new JWSObject(header, PAYLOAD);

		assertEquals("State check", JWSObject.State.UNSIGNED, jwsObject.getState());


		MACSigner signer = new MACSigner(sharedSecret);
		assertEquals("Shared secret check", sharedSecret, signer.getSecret());

		jwsObject.sign(signer);

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());


		MACVerifier verifier = new MACVerifier(sharedSecret);
		assertEquals("Shared secret check", sharedSecret, verifier.getSecret());

		boolean verified = jwsObject.verify(verifier);

		assertTrue("Verified signature", verified);

		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
	}


	public void testSignWithTestVector()
		throws Exception {

		JWSHeader header = JWSHeader.parse(B64_HEADER);

		JWSSigner signer = new MACSigner(sharedSecret);

		Base64URL b64sigComputed = signer.sign(header, SIGNABLE);

		assertEquals("Signature check", B64_SIG, b64sigComputed);
	}


	public void testVerifyWithTestVector()
		throws Exception {

		JWSHeader header = JWSHeader.parse(B64_HEADER);

		JWSVerifier verifier = new MACVerifier(sharedSecret);

		boolean verified = verifier.verify(header, SIGNABLE, B64_SIG);

		assertTrue("Signature check", verified);
	}


	public void testSignAndVerifyWithRandomSecret()
		throws Exception {

		Map<JWSAlgorithm, Integer> secretLengthMap = new HashMap<>();
		secretLengthMap.put(JWSAlgorithm.HS256, 256);
		secretLengthMap.put(JWSAlgorithm.HS384, 384);
		secretLengthMap.put(JWSAlgorithm.HS512, 512);

		for (Map.Entry<JWSAlgorithm, Integer> en: secretLengthMap.entrySet()) {

			JWSAlgorithm alg = en.getKey();
			int bitLength = en.getValue();

			byte[] sharedSecret = new byte[ByteUtils.byteLength(bitLength)];
			new SecureRandom().nextBytes(sharedSecret);

			// Create HMAC signer
			MACSigner signer = new MACSigner(sharedSecret);
			assertArrayEquals(sharedSecret, signer.getSecretKey().getEncoded());

			// Prepare JWS object with "Hello, world!" payload
			JWSObject jwsObject = new JWSObject(new JWSHeader(alg), new Payload("Hello, world!"));

			// Apply the HMAC
			jwsObject.sign(signer);

			assertEquals(jwsObject.getState(), JWSObject.State.SIGNED);

			// To serialize to compact form, produces something like
			// eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
			String s = jwsObject.serialize();

			// To parse the JWS and verify it, e.g. on client-side
			jwsObject = JWSObject.parse(s);

			MACVerifier verifier = new MACVerifier(sharedSecret);
			assertArrayEquals(sharedSecret, verifier.getSecretKey().getEncoded());

			assertTrue(jwsObject.verify(verifier));

			assertEquals("Hello, world!", jwsObject.getPayload().toString());
		}
	}


	public void testSignAndVerifyWithStringSecret()
		throws Exception {

		Map<JWSAlgorithm, Integer> secretLengthMap = new HashMap<>();
		secretLengthMap.put(JWSAlgorithm.HS256, 256);
		secretLengthMap.put(JWSAlgorithm.HS384, 384);
		secretLengthMap.put(JWSAlgorithm.HS512, 512);

		for (Map.Entry<JWSAlgorithm, Integer> en: secretLengthMap.entrySet()) {

			JWSAlgorithm alg = en.getKey();
			int bitLength = en.getValue();

			byte[] sharedSecret = new byte[ByteUtils.byteLength(bitLength)];
			new SecureRandom().nextBytes(sharedSecret);

			final String stringSecret = new String(sharedSecret);

			JWSObject jwsObject = new JWSObject(new JWSHeader(alg), PAYLOAD);

			assertEquals("State check", JWSObject.State.UNSIGNED, jwsObject.getState());


			MACSigner signer = new MACSigner(stringSecret);
			assertEquals("Shared secret string check", stringSecret, signer.getSecretString());

			jwsObject.sign(signer);

			assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());


			MACVerifier verifier = new MACVerifier(stringSecret);
			assertEquals("Shared secret string check", stringSecret, verifier.getSecretString());

			boolean verified = jwsObject.verify(verifier);

			assertTrue("Verified signature", verified);

			assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
		}
	}


	public void testSignAndVerifyWithSecretKey()
		throws Exception {

		Map<JWSAlgorithm, Integer> secretLengthMap = new HashMap<>();
		secretLengthMap.put(JWSAlgorithm.HS256, 256);
		secretLengthMap.put(JWSAlgorithm.HS384, 384);
		secretLengthMap.put(JWSAlgorithm.HS512, 512);

		for (Map.Entry<JWSAlgorithm, Integer> en: secretLengthMap.entrySet()) {

			JWSAlgorithm alg = en.getKey();
			int bitLength = en.getValue();

			byte[] sharedSecret = new byte[ByteUtils.byteLength(bitLength)];
			new SecureRandom().nextBytes(sharedSecret);
			SecretKey secretKey = new SecretKeySpec(sharedSecret, "HMACSHA" + bitLength);

			// Create HMAC signer
			MACSigner signer = new MACSigner(secretKey);
			assertEquals(secretKey, signer.getSecretKey());
			assertArrayEquals(sharedSecret, signer.getSecretKey().getEncoded());

			// Prepare JWS object with "Hello, world!" payload
			JWSObject jwsObject = new JWSObject(new JWSHeader(alg), new Payload("Hello, world!"));

			// Apply the HMAC
			jwsObject.sign(signer);

			assertEquals(jwsObject.getState(), JWSObject.State.SIGNED);

			// To serialize to compact form, produces something like
			// eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
			String s = jwsObject.serialize();

			// To parse the JWS and verify it, e.g. on client-side
			jwsObject = JWSObject.parse(s);

			MACVerifier verifier = new MACVerifier(secretKey);
			assertEquals(secretKey, verifier.getSecretKey());
			assertArrayEquals(sharedSecret, verifier.getSecretKey().getEncoded());

			assertTrue(jwsObject.verify(verifier));

			assertEquals("Hello, world!", jwsObject.getPayload().toString());
		}
	}


	public void testSignAndVerifyWithJWK()
		throws Exception {

		Map<JWSAlgorithm, Integer> secretLengthMap = new HashMap<>();
		secretLengthMap.put(JWSAlgorithm.HS256, 256);
		secretLengthMap.put(JWSAlgorithm.HS384, 384);
		secretLengthMap.put(JWSAlgorithm.HS512, 512);

		for (Map.Entry<JWSAlgorithm, Integer> en: secretLengthMap.entrySet()) {

			JWSAlgorithm alg = en.getKey();
			int bitLength = en.getValue();

			byte[] sharedSecret = new byte[ByteUtils.byteLength(bitLength)];
			new SecureRandom().nextBytes(sharedSecret);
			SecretKey secretKey = new SecretKeySpec(sharedSecret, "HMACSHA" + bitLength);
			OctetSequenceKey jwk = new OctetSequenceKey.Builder(secretKey)
				.build();

			// Create HMAC signer
			MACSigner signer = new MACSigner(jwk);
			assertNotEquals(secretKey, signer.getSecretKey());
			assertArrayEquals(sharedSecret, signer.getSecretKey().getEncoded());

			// Prepare JWS object with "Hello, world!" payload
			JWSObject jwsObject = new JWSObject(new JWSHeader(alg), new Payload("Hello, world!"));

			// Apply the HMAC
			jwsObject.sign(signer);

			assertEquals(jwsObject.getState(), JWSObject.State.SIGNED);

			// To serialize to compact form, produces something like
			// eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onO9Ihudz3WkiauDO2Uhyuz0Y18UASXlSc1eS0NkWyA
			String s = jwsObject.serialize();

			// To parse the JWS and verify it, e.g. on client-side
			jwsObject = JWSObject.parse(s);

			MACVerifier verifier = new MACVerifier(jwk);
			assertNotEquals(secretKey, verifier.getSecretKey());
			assertArrayEquals(sharedSecret, verifier.getSecretKey().getEncoded());

			assertTrue(jwsObject.verify(verifier));

			assertEquals("Hello, world!", jwsObject.getPayload().toString());
		}
	}


	public void testParseAndVerifyTestVector()
		throws Exception {

		String s = B64_HEADER + "." + PAYLOAD.toBase64URL() + "." + B64_SIG;

		JWSObject jwsObject = JWSObject.parse(s);

		assertEquals(s, jwsObject.getParsedString());

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());

		JWSVerifier verifier = new MACVerifier(sharedSecret);

		boolean verified = jwsObject.verify(verifier);

		assertTrue("Signature check", verified);

		assertEquals("State check", JWSObject.State.VERIFIED, jwsObject.getState());
	}


	public void testCookbookExample()
		throws Exception {

		// See http://tools.ietf.org/html/rfc7520#section-4.4.3

		String json ="{"+
			"\"kty\":\"oct\","+
			"\"kid\":\"018c0ae5-4d9b-471b-bfd6-eef314bc7037\","+
			"\"use\":\"sig\","+
			"\"k\":\"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\""+
			"}";

		OctetSequenceKey jwk = OctetSequenceKey.parse(json);

		String jws = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LW"+
			"VlZjMxNGJjNzAzNyJ9"+
			"."+
			"SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH"+
			"lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk"+
			"b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm"+
			"UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"+
			"."+
			"s0h6KThzkfBBBkLspW1h84VsJZFTsPPqMDA7g1Md7p0";

		JWSObject jwsObject = JWSObject.parse(jws);

		assertEquals(JWSAlgorithm.HS256, jwsObject.getHeader().getAlgorithm());
		assertEquals("018c0ae5-4d9b-471b-bfd6-eef314bc7037", jwsObject.getHeader().getKeyID());

		JWSVerifier verifier = new MACVerifier(jwk.toByteArray());

		assertTrue(jwsObject.verify(verifier));

		assertEquals("SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IH" +
			"lvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBk" +
			"b24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcm" +
			"UgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4", jwsObject.getPayload().toBase64URL().toString());
	}


	public void testCritHeaderParamIgnore()
		throws Exception {

		byte[] secret = new byte[64];
		new SecureRandom().nextBytes(secret);

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS512).
			customParam(JWTClaimNames.EXPIRATION_TIME, "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList(JWTClaimNames.EXPIRATION_TIME))).
			build();

		JWSObject jwsObject = new JWSObject(header, PAYLOAD);

		MACSigner signer = new MACSigner(secret);

		jwsObject.sign(signer);

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());

		Set<String> defCritHeaders = new HashSet<>(Collections.singletonList(JWTClaimNames.EXPIRATION_TIME));

		for (MACVerifier verifier: Arrays.asList(
			new MACVerifier(secret, defCritHeaders),
			new MACVerifier(new SecretKeySpec(secret, "HMACSHA512"), defCritHeaders),
			new MACVerifier(new OctetSequenceKey.Builder(secret).build(), defCritHeaders))) {

			boolean verified = jwsObject.verify(verifier);

			assertTrue("Verified signature", verified);

			assertEquals("State check",JWSObject.State.VERIFIED, jwsObject.getState());
		}
	}


	public void testCritHeaderParamReject()
		throws Exception {

		byte[] secret = new byte[64];
		new SecureRandom().nextBytes(secret);

		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS512).
			customParam(JWTClaimNames.EXPIRATION_TIME, "2014-04-24").
			criticalParams(new HashSet<>(Collections.singletonList(JWTClaimNames.EXPIRATION_TIME))).
			build();

		JWSObject jwsObject = new JWSObject(header, PAYLOAD);

		MACSigner signer = new MACSigner(secret);

		jwsObject.sign(signer);

		assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());

		for (MACVerifier verifier: Arrays.asList(
			new MACVerifier(secret),
			new MACVerifier(new SecretKeySpec(secret, "HMACSHA512")),
			new MACVerifier(new OctetSequenceKey.Builder(secret).build()))) {

			boolean verified = jwsObject.verify(verifier);

			assertFalse("Verified signature", verified);

			assertEquals("State check", JWSObject.State.SIGNED, jwsObject.getState());
		}
	}


	public void testConstructorMustRejectSecretShorterThan256Bits() {

		byte[] secret = new byte[31];
		new SecureRandom().nextBytes(secret);

		try {
			new MACSigner(secret);
			fail();
		} catch (JOSEException e) {
			assertEquals("The secret length must be at least 256 bits", e.getMessage());
		}

		try {
			new MACVerifier(secret);
			fail();
		} catch (JOSEException e) {
			assertEquals("The secret length must be at least 256 bits", e.getMessage());
		}
	}


	public void testRejectShortSecretOnSignAndVerify_byteArrayConstructor_HS384()
		throws Exception {

		byte[] secret = new byte[ByteUtils.byteLength(384) - 1];
		new SecureRandom().nextBytes(secret);

		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS384), new Payload("Hello world!"));

		JWSSigner signer = new MACSigner(secret);
		try {
			jwsObject.sign(signer);
			fail();
		} catch (JOSEException e) {
			assertEquals("The HS384 algorithm is not allowed or supported by the JWS signer: Supported algorithms: [HS256]", e.getMessage());
		}

		// Sign with min required length
		byte[] correctSecret = new byte[ByteUtils.byteLength(384)];
		new SecureRandom().nextBytes(correctSecret);
		jwsObject.sign(new MACSigner(correctSecret));

		JWSVerifier verifier = new MACVerifier(secret);
		try {
			jwsObject.verify(verifier);
			fail();
		} catch (JOSEException e) {
			assertEquals("The secret length for HS384 must be at least 384 bits", e.getMessage());
		}
	}


	public void testRejectShortSecretOnSignAndVerify_byteArrayConstructor_HS512()
		throws Exception {

		byte[] secret = new byte[ByteUtils.byteLength(512) - 1];
		new SecureRandom().nextBytes(secret);

		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS512), new Payload("Hello world!"));

		JWSSigner signer = new MACSigner(secret);
		try {
			jwsObject.sign(signer);
			fail();
		} catch (JOSEException e) {
			assertEquals("The HS512 algorithm is not allowed or supported by the JWS signer: Supported algorithms: [HS256, HS384]", e.getMessage());
		}

		// Sign with min required length
		byte[] correctSecret = new byte[ByteUtils.byteLength(512)];
		new SecureRandom().nextBytes(correctSecret);
		jwsObject.sign(new MACSigner(correctSecret));

		JWSVerifier verifier = new MACVerifier(secret);
		try {
			jwsObject.verify(verifier);
			fail();
		} catch (JOSEException e) {
			assertEquals("The secret length for HS512 must be at least 512 bits", e.getMessage());
		}
	}


	public void testRejectShortSecretOnSignAndVerify_secretKeyConstructor_HS384()
		throws Exception {

		byte[] secret = new byte[ByteUtils.byteLength(384) - 1];
		new SecureRandom().nextBytes(secret);
		SecretKey secretKey = new SecretKeySpec(secret, "HMACSHA384");

		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS384), new Payload("Hello world!"));

		JWSSigner signer = new MACSigner(secretKey);
		try {
			jwsObject.sign(signer);
			fail();
		} catch (JOSEException e) {
			assertEquals("The HS384 algorithm is not allowed or supported by the JWS signer: Supported algorithms: [HS256]", e.getMessage());
		}

		// Sign with min required length
		byte[] correctSecret = new byte[ByteUtils.byteLength(384)];
		new SecureRandom().nextBytes(correctSecret);
		jwsObject.sign(new MACSigner(correctSecret));

		JWSVerifier verifier = new MACVerifier(secretKey);
		try {
			jwsObject.verify(verifier);
			fail();
		} catch (JOSEException e) {
			assertEquals("The secret length for HS384 must be at least 384 bits", e.getMessage());
		}
	}


	public void testRejectShortSecretOnSignAndVerify_secretKeyConstructor_HS512()
		throws Exception {

		byte[] secret = new byte[ByteUtils.byteLength(512) - 1];
		new SecureRandom().nextBytes(secret);
		SecretKey secretKey = new SecretKeySpec(secret, "HMACSHA512");

		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS512), new Payload("Hello world!"));

		JWSSigner signer = new MACSigner(secretKey);
		try {
			jwsObject.sign(signer);
			fail();
		} catch (JOSEException e) {
			assertEquals("The HS512 algorithm is not allowed or supported by the JWS signer: Supported algorithms: [HS256, HS384]", e.getMessage());
		}

		// Sign with min required length
		byte[] correctSecret = new byte[ByteUtils.byteLength(512)];
		new SecureRandom().nextBytes(correctSecret);
		jwsObject.sign(new MACSigner(correctSecret));

		JWSVerifier verifier = new MACVerifier(secretKey);
		try {
			jwsObject.verify(verifier);
			fail();
		} catch (JOSEException e) {
			assertEquals("The secret length for HS512 must be at least 512 bits", e.getMessage());
		}
	}


	public void testAllowLongerSecretOnSign()
		throws Exception {

		byte[] secret = new byte[ByteUtils.byteLength(512)];
		new SecureRandom().nextBytes(secret);

		JWSSigner signer = new MACSigner(secret);

		JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS384), new Payload("Hello world!"));
		jwsObject.sign(signer);
	}
}
