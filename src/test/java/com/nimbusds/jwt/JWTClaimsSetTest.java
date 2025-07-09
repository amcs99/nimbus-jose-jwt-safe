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

package com.nimbusds.jwt;


import com.google.gson.stream.JsonReader;
import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.util.DateUtils;
import junit.framework.TestCase;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.text.ParseException;
import java.util.*;

import static com.nimbusds.jose.util.JSONArrayUtilsTest.createJSONArrayWithNesting;
import static com.nimbusds.jose.util.JSONObjectUtilsTest.createJSONObjectWithNesting;


/**
 * Tests JWT claims set serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @author Joey Zhao
 * @version 2025-02-25
 */
public class JWTClaimsSetTest extends TestCase {


	public void testReservedNames() {

		Set<String> names = JWTClaimsSet.getRegisteredNames();

		assertTrue(names.contains(JWTClaimNames.ISSUER));
		assertTrue(names.contains(JWTClaimNames.SUBJECT));
		assertTrue(names.contains(JWTClaimNames.AUDIENCE));
		assertTrue(names.contains(JWTClaimNames.EXPIRATION_TIME));
		assertTrue(names.contains(JWTClaimNames.NOT_BEFORE));
		assertTrue(names.contains(JWTClaimNames.ISSUED_AT));
		assertTrue(names.contains(JWTClaimNames.JWT_ID));

		assertEquals(7, names.size());
	}


	public void testRun() {

		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		// JWT time claim precision is seconds
		final Date NOW =  new Date(new Date().getTime() / 1000 * 1000);

		// iss
		assertNull("iss init check", builder.build().getIssuer());
		builder.issuer("http://issuer.com");
		assertEquals("iss set check", "http://issuer.com", builder.build().getIssuer());

		// sub
		assertNull("sub init check", builder.build().getSubject());
		builder.subject("http://subject.com");
		assertEquals("sub set check", "http://subject.com", builder.build().getSubject());

		// aud
		assertTrue("aud init check", builder.build().getAudience().isEmpty());
		builder.audience(Collections.singletonList("http://audience.com"));
		assertEquals("aud set check", "http://audience.com", builder.build().getAudience().get(0));

		// exp
		assertNull("exp init check", builder.build().getExpirationTime());
		builder.expirationTime(NOW);
		assertEquals("exp set check", NOW, builder.build().getExpirationTime());

		// nbf
		assertNull("nbf init check", builder.build().getNotBeforeTime());
		builder.notBeforeTime(NOW);
		assertEquals("nbf set check", NOW, builder.build().getNotBeforeTime());

		// iat
		assertNull("iat init check", builder.build().getIssueTime());
		builder.issueTime(NOW);
		assertEquals("iat set check", NOW, builder.build().getIssueTime());

		// jti
		assertNull("jti init check", builder.build().getJWTID());
		builder.jwtID("123");
		assertEquals("jti set check", "123", builder.build().getJWTID());

		// no custom claims
		assertEquals(7, builder.build().getClaims().size());

		// x-custom
		builder.claim("x-custom", "abc");
		assertEquals("abc", (String) builder.build().getClaim("x-custom"));
		
		// claims set so far
		Map<String,Object> all = builder.getClaims();
		
		assertEquals("iss parse check map", "http://issuer.com", (String)all.get(JWTClaimNames.ISSUER));
		assertEquals("sub parse check map", "http://subject.com", (String)all.get(JWTClaimNames.SUBJECT));
		assertEquals("aud parse check map", "http://audience.com", (String)((List)all.get(JWTClaimNames.AUDIENCE)).get(0));
		assertEquals("exp parse check map", NOW, all.get(JWTClaimNames.EXPIRATION_TIME));
		assertEquals("nbf parse check map", NOW, all.get(JWTClaimNames.NOT_BEFORE));
		assertEquals("iat parse check map", NOW, all.get(JWTClaimNames.ISSUED_AT));
		assertEquals("jti parse check map", "123", (String)all.get(JWTClaimNames.JWT_ID));
		assertEquals("abc", (String)all.get("x-custom"));
		assertEquals(8, all.size());


		// serialise
		Map<String, Object> json = builder.build().toJSONObject();

		assertEquals(8, json.size());

		// parse back
		JWTClaimsSet claimsSet = null;
		try {
			claimsSet = JWTClaimsSet.parse(json);

		} catch (java.text.ParseException e) {

			fail(e.getMessage());
		}

		assertEquals("iss parse check", "http://issuer.com", claimsSet.getIssuer());
		assertEquals("sub parse check", "http://subject.com", claimsSet.getSubject());
		assertEquals("aud parse check", "http://audience.com", claimsSet.getAudience().get(0));
		assertEquals("exp parse check", NOW, claimsSet.getExpirationTime());
		assertEquals("nbf parse check", NOW, claimsSet.getNotBeforeTime());
		assertEquals("iat parse check", NOW, claimsSet.getIssueTime());
		assertEquals("jti parse check", "123", claimsSet.getJWTID());
		assertEquals("abc", (String)claimsSet.getClaim("x-custom"));
		assertEquals(8, claimsSet.getClaims().size());


		all = claimsSet.getClaims();

		assertEquals("iss parse check map", "http://issuer.com", (String)all.get(JWTClaimNames.ISSUER));
		assertEquals("sub parse check map", "http://subject.com", (String)all.get(JWTClaimNames.SUBJECT));
		assertEquals("aud parse check map", "http://audience.com", (String)((List)all.get(JWTClaimNames.AUDIENCE)).get(0));
		assertEquals("exp parse check map", NOW, all.get(JWTClaimNames.EXPIRATION_TIME));
		assertEquals("nbf parse check map", NOW, all.get(JWTClaimNames.NOT_BEFORE));
		assertEquals("iat parse check map", NOW, all.get(JWTClaimNames.ISSUED_AT));
		assertEquals("jti parse check map", "123", (String)all.get(JWTClaimNames.JWT_ID));
		assertEquals("abc", (String)all.get("x-custom"));
		assertEquals(8, all.size());
	}
	
	
	public void testToPayload() {
		
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.claim("xxx", null)
			.build();
		
		assertEquals(jwtClaimsSet.toJSONObject(), jwtClaimsSet.toPayload().toJSONObject());

		assertEquals(jwtClaimsSet.toJSONObject(false), jwtClaimsSet.toPayload(false).toJSONObject());
		assertEquals(jwtClaimsSet.toJSONObject(true), jwtClaimsSet.toPayload(true).toJSONObject());
	}


	public void testDateConversion() {

		final Date ONE_MIN_AFTER_EPOCH = new Date(1000*60);

		JWTClaimsSet cs = new JWTClaimsSet.Builder()
			.issueTime(ONE_MIN_AFTER_EPOCH)
			.notBeforeTime(ONE_MIN_AFTER_EPOCH)
			.expirationTime(ONE_MIN_AFTER_EPOCH)
			.build();

		Map<String, Object> json = cs.toJSONObject();

		assertEquals(60L, json.get(JWTClaimNames.ISSUED_AT));
		assertEquals(60L, json.get(JWTClaimNames.NOT_BEFORE));
		assertEquals(60L, json.get(JWTClaimNames.EXPIRATION_TIME));
	}
	
	
	public void testCustomClaim() {
		
		JWTClaimsSet cs = new JWTClaimsSet.Builder().claim("locale", "bg-BG").build();
		assertEquals(1, cs.getClaims().size());

		cs = new JWTClaimsSet.Builder().claim("locale", null).build();
		assertNull(cs.getClaim("locale"));
		assertEquals(1, cs.getClaims().size());
	}


	public void testNullCustomClaim() {

		JWTClaimsSet cs = new JWTClaimsSet.Builder().claim("locale", null).build();
		assertNull(cs.getClaim("locale"));
		assertEquals(1, cs.getClaims().size());
	}
	
	
	public void testSetCustomClaims() {
		
		JWTClaimsSet cs = new JWTClaimsSet.Builder()
			.claim("locale", "bg-BG")
			.claim("locale", "es-ES")
			.claim("ip", "127.0.0.1")
			.build();

		assertEquals(2, cs.getClaims().size());
		
		assertEquals("es-ES", (String)cs.getClaims().get("locale"));
		assertEquals("127.0.0.1", (String)cs.getClaims().get("ip"));
	}
	
	
	public void testGetClaimValueNotSpecified() {
		
		JWTClaimsSet cs = new JWTClaimsSet.Builder().build();
		
		assertNull(cs.getClaim("xyz"));
	}
	
	
	public void testSetClaimNull() {
		
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		
		builder.issuer("http://example.com");
		assertEquals("http://example.com", builder.build().getIssuer());
		builder = builder.claim(JWTClaimNames.ISSUER, null);
		assertNull(builder.build().getIssuer());
		
		builder.subject("alice");
		assertEquals("alice", builder.build().getSubject());
		builder.claim(JWTClaimNames.SUBJECT, null);
		assertNull(builder.build().getSubject());
		
		List<String> audList = new ArrayList<>();
		audList.add("http://client.example.com");
		builder.audience(audList);
		assertEquals("http://client.example.com", builder.build().getAudience().get(0));
		builder = builder.claim(JWTClaimNames.AUDIENCE, null);
		assertTrue(builder.build().getAudience().isEmpty());
		
		Date now = new Date();
		builder.expirationTime(now);
		assertEquals(now, builder.build().getExpirationTime());
		builder = builder.claim(JWTClaimNames.EXPIRATION_TIME, null);
		assertNull(builder.build().getExpirationTime());
		
		builder.notBeforeTime(now);
		assertEquals(now, builder.build().getNotBeforeTime());
		builder = builder.claim(JWTClaimNames.NOT_BEFORE, null);
		assertNull(builder.build().getNotBeforeTime());
		
		builder.issueTime(now);
		assertEquals(now, builder.build().getIssueTime());
		builder = builder.claim(JWTClaimNames.ISSUED_AT, null);
		assertNull(builder.build().getIssueTime());
		
		builder.jwtID("123");
		assertEquals("123", builder.build().getJWTID());
		builder = builder.claim(JWTClaimNames.JWT_ID, null);
		assertNull(builder.build().getJWTID());
	}
	
	
	public void testGetClaimTyped()
		throws Exception {
		
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		
		builder.claim("string", "abc");
		assertEquals("abc", builder.build().getStringClaim("string"));
		
		builder.claim("boolean", false);
		assertFalse(builder.build().getBooleanClaim("boolean"));
		
		builder.claim("integer", 123);
		assertEquals(123, builder.build().getIntegerClaim("integer").intValue());
		
		builder.claim("long", 456L);
		assertEquals(456L, builder.build().getLongClaim("long").longValue());

		Date date = new Date(999000L);
		builder.claim("date", date);
		assertEquals(date, builder.build().getDateClaim("date"));

		// Convert Unix timestamp to Java date
		builder.claim("date-long", 999L);
		assertEquals(new Date(999000L), builder.build().getDateClaim("date-long"));
		
		builder.claim("float", 3.14f);
		assertEquals(3.14f, builder.build().getFloatClaim("float"));
		
		builder.claim("double", 3.14d);
		assertEquals(3.14d, builder.build().getDoubleClaim("double"));
	}

	public void testGetClaimAsString()
		throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

        builder.claim("string", null);
        assertNull(builder.build().getClaimAsString("string"));

        builder.claim("number", 2);
        assertEquals("2", builder.build().getClaimAsString("number"));

        builder.claim("number", new Integer(2));
        assertEquals("2", builder.build().getClaimAsString("number"));

        builder.claim("boolean", true);
        assertEquals("true", builder.build().getClaimAsString("boolean"));

        builder.claim("boolean", Boolean.TRUE);
        assertEquals("true", builder.build().getClaimAsString("boolean"));

        builder.claim("object", new Object());
        try {
            builder.build().getClaimAsString("object");
            fail();
        } catch (ParseException e) {
            // ok
        }
    }
	
	
	public void testGetClaimTypedNull()
		throws Exception {
		
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		
		builder.claim("string", null);
		assertNull(builder.build().getStringClaim("string"));
		
		builder.claim("boolean", null);
		assertNull(builder.build().getBooleanClaim("boolean"));
		
		builder.claim("integer", null);
		assertNull(builder.build().getIntegerClaim("integer"));
		
		builder.claim("long", null);
		assertNull(builder.build().getLongClaim("long"));
		
		builder.claim("date", null);
		assertNull(builder.build().getDateClaim("date"));
		
		builder.claim("float", null);
		assertNull(builder.build().getFloatClaim("float"));
		
		builder.claim("double", null);
		assertNull(builder.build().getDoubleClaim("double"));
	}
	
	
	public void testGetClaimTypedParseException() {
		
		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();
		
		builder.claim("string", 3.14);
		
		try {
			builder.build().getStringClaim("string");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		builder.claim("boolean", "123");
		
		try {
			builder.build().getBooleanClaim("boolean");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		builder.claim("integer", true);
		
		try {
			builder.build().getIntegerClaim("integer");
			
			fail();
			
		} catch (ParseException e) {
			// ok
		}
		
		builder.claim("long", "abc");
		
		try {
			builder.build().getLongClaim("long");
			
			fail();
			
		} catch (ParseException e) {
			// ok
		}
		
		builder.claim("date", "abc");
		
		try {
			builder.build().getDateClaim("date");
			
			fail();
			
		} catch (ParseException e) {
			// ok
		}
		
		builder.claim("float", true);
		
		try {
			builder.build().getFloatClaim("float");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		builder.claim("double", "abc");
		
		try {
			builder.build().getDoubleClaim("double");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
	}


	public void testStringAudience()
		throws Exception {

		Map<String, Object> o = new LinkedHashMap<>();
		o.put(JWTClaimNames.AUDIENCE, "http://example.com");

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(JSONObjectUtils.toJSONString(o));

		assertEquals("http://example.com", jwtClaimsSet.getAudience().get(0));
		assertEquals(1, jwtClaimsSet.getAudience().size());
	}


	public void testStringArrayAudience()
		throws Exception {

		Map<String, Object> o = new LinkedHashMap<>();
		o.put(JWTClaimNames.AUDIENCE, Collections.singletonList("http://example.com"));

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(JSONObjectUtils.toJSONString(o));

		assertEquals("http://example.com", jwtClaimsSet.getAudience().get(0));
		assertEquals(1, jwtClaimsSet.getAudience().size());
	}


	public void testStringArrayMultipleAudience()
		throws Exception {

		Map<String, Object> o = new LinkedHashMap<>();
		o.put(JWTClaimNames.AUDIENCE, Arrays.asList("http://example.com", "http://example2.com"));

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(JSONObjectUtils.toJSONString(o));

		assertEquals("http://example.com", jwtClaimsSet.getAudience().get(0));
		assertEquals("http://example2.com", jwtClaimsSet.getAudience().get(1));
		assertEquals(2, jwtClaimsSet.getAudience().size());
	}


	public void testParseExampleIDToken()
		throws Exception {

		String json = "{\"exp\":1384798159,\"sub\":\"alice\",\"aud\":[\"000001\"],\"iss\":\"https:\\/\\/localhost:8080\\/c2id\",\"login_geo\":{\"long\":\"37.3956\",\"lat\":\"-122.076\"},\"login_ip\":\"185.7.248.1\",\"iat\":1384797259,\"acr\":\"urn:mace:incommon:iap:silver\",\"c_hash\":\"vwVj99I7FizReIt5q3UwhQ\",\"amr\":[\"mfa\"]}";

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(json);

		assertEquals(1384798159L, claimsSet.getExpirationTime().getTime() / 1000);
		assertEquals(1384797259L, claimsSet.getIssueTime().getTime() / 1000);

		assertEquals("alice", claimsSet.getSubject());

		assertEquals("000001", claimsSet.getAudience().get(0));
		assertEquals(1, claimsSet.getAudience().size());

		assertEquals("https://localhost:8080/c2id", claimsSet.getIssuer());

		assertEquals("urn:mace:incommon:iap:silver", claimsSet.getStringClaim("acr"));

		assertEquals("vwVj99I7FizReIt5q3UwhQ", claimsSet.getStringClaim("c_hash"));

		assertEquals("mfa", ((List<String>)claimsSet.getClaim("amr")).get(0));
		assertEquals(1, ((List<String>)claimsSet.getClaim("amr")).size());

		assertEquals("185.7.248.1", claimsSet.getStringClaim("login_ip"));

		Map<String, Object> geoLoc = (Map<String, Object>)claimsSet.getClaim("login_geo");

		// {"long":"37.3956","lat":"-122.076"}
		assertEquals("37.3956", (String)geoLoc.get("long"));
		assertEquals("-122.076", (String)geoLoc.get("lat"));
	}


	public void testSingleValuedAudienceSetter() {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();
		assertTrue(claimsSet.getAudience().isEmpty());

		claimsSet = new JWTClaimsSet.Builder().audience("123").build();
		assertEquals("123", claimsSet.getAudience().get(0));
		assertEquals(1, claimsSet.getAudience().size());

		claimsSet = new JWTClaimsSet.Builder().audience((String) null).build();
		assertTrue(claimsSet.getAudience().isEmpty());
	}


	public void testSerializeSingleValuedAudience()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().audience("123").build();

		Map<String, Object> jsonObject = claimsSet.toJSONObject();

		assertEquals("123", (String)jsonObject.get(JWTClaimNames.AUDIENCE));
		assertEquals(1, jsonObject.size());

		claimsSet = JWTClaimsSet.parse(claimsSet.toString());
		assertEquals("123", claimsSet.getAudience().get(0));
		assertEquals(1, claimsSet.getAudience().size());
	}


	public void testGetAllClaimsEmpty() {

		assertTrue(new JWTClaimsSet.Builder().build().getClaims().isEmpty());
	}


	public void testParseOIDCAuthz()
		throws Exception {

		String json = "{\"sub\":\"alice\",\"irt\":true,\"rft\":\"YWxpY2U.aHR0cDovL2NsaWVudDEuZXhhbXBsZS5jb20.rsKHqBpyEh-MMtllO7chHg\",\"aud\":[\"http:\\/\\/userinfo.example.com\"],\"iss\":\"http:\\/\\/oidc.example.com\",\"ate\":\"IDENTIFIER\",\"lng\":true,\"iat\":1420544052,\"cid\":\"http:\\/\\/client1.example.com\"}";
		JWTClaimsSet.parse(json);
	}


	public void testAudienceParsing()
		throws Exception {

		Map<String, Object> jsonObject = new LinkedHashMap<>();
		List<Object> aud = new ArrayList<>();
		aud.add("client-1");
		aud.add("client-2");
		jsonObject.put(JWTClaimNames.AUDIENCE, aud);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);
		assertEquals("client-1", claimsSet.getAudience().get(0));
		assertEquals("client-2", claimsSet.getAudience().get(1));
		assertEquals(2, claimsSet.getAudience().size());
	}


	public void testGetStringArrayClaim()
		throws Exception {

		Map<String, Object> jsonObject = new LinkedHashMap<>();
		List<Object> jsonArray = new ArrayList<>();
		jsonArray.add("client-1");
		jsonArray.add("client-2");
		jsonObject.put("array", jsonArray);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		String[] strings = claimsSet.getStringArrayClaim("array");
		assertEquals("client-1", strings[0]);
		assertEquals("client-2", strings[1]);
		assertEquals(2, strings.length);
	}


	public void testGetInvalidStringArrayClaim()
		throws Exception {

		Map<String, Object> jsonObject = new LinkedHashMap<>();
		List<Object> jsonArray = new ArrayList<>();
		jsonArray.add("client-1");
		jsonArray.add(0);
		jsonObject.put("array", jsonArray);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		try {
			claimsSet.getStringArrayClaim("array");
			fail();
		} catch (ParseException e) {
			// ok
		}
	}


	public void testGetNullStringArrayClaim()
		throws Exception {

		Map<String, Object> jsonObject = new LinkedHashMap<>();

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		assertNull(claimsSet.getStringArrayClaim("array"));
	}


	public void testGetStringListClaim()
		throws Exception {

		Map<String, Object> jsonObject = new LinkedHashMap<>();
		List<Object> jsonArray = new ArrayList<>();
		jsonArray.add("client-1");
		jsonArray.add("client-2");
		jsonObject.put("array", jsonArray);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		List<String> strings = claimsSet.getStringListClaim("array");
		assertEquals("client-1", strings.get(0));
		assertEquals("client-2", strings.get(1));
		assertEquals(2, strings.size());
	}


	public void testGetInvalidStringListClaim()
		throws Exception {

		Map<String, Object> jsonObject = new LinkedHashMap<>();
		List<Object> jsonArray = new ArrayList<>();
		jsonArray.add("client-1");
		jsonArray.add(0);
		jsonObject.put("array", jsonArray);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		try {
			claimsSet.getStringListClaim("array");
			fail();
		} catch (ParseException e) {
			// ok
		}
	}


	public void testGetNullStringListClaim()
		throws Exception {

		Map<String, Object> jsonObject = new LinkedHashMap<>();

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		assertNull(claimsSet.getStringListClaim("array"));
	}


	public void testExtendedCyrillicChars()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("Владимир Джувинов").build();

		String json = JSONObjectUtils.toJSONString(claimsSet.toJSONObject());

		claimsSet = JWTClaimsSet.parse(json);

		assertEquals("Владимир Джувинов", claimsSet.getSubject());
	}


	public void testExtendedLatinChars()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim("fullName", "João").build();

		String json = JSONObjectUtils.toJSONString(claimsSet.toJSONObject());

		Base64URL base64URL = Base64URL.encode(json);

		claimsSet = JWTClaimsSet.parse(base64URL.decodeToString());

		assertEquals("João", claimsSet.getStringClaim("fullName"));
	}
	
	
	public void testURIClaim()
		throws Exception {
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim("uri", URI.create("https://example.com").toString()).build();
		
		String json = JSONObjectUtils.toJSONString(claimsSet.toJSONObject());
		
		claimsSet = JWTClaimsSet.parse(json);
		
		assertEquals(URI.create("https://example.com"), claimsSet.getURIClaim("uri"));
		
		assertNull(claimsSet.getURIClaim("no-such-uri-claim"));
	}
	
	
	public void testParseInvalidURIClaim()
		throws Exception {
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim("uri", "a b c").build();
		
		String json = JSONObjectUtils.toJSONString(claimsSet.toJSONObject());
		
		claimsSet = JWTClaimsSet.parse(json);
		
		try {
			claimsSet.getURIClaim("uri");
			fail();
		} catch (ParseException e) {
			assertEquals("The \"uri\" claim is not a URI: Illegal character in path at index 1: a b c", e.getMessage());
		}
	}


	public void testSerializeIgnoreNullValues() {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer(null)
			.subject(null)
			.audience((String)null)
			.expirationTime(null)
			.issueTime(null)
			.notBeforeTime(null)
			.jwtID(null)
			.claim("locale", null)
			.build();

		assertTrue(claimsSet.toJSONObject().isEmpty());
	}


	public void testTransformer() {

		JWTClaimsSetTransformer<String> transformer = new JWTClaimsSetTransformer<String>() {
			@Override
			public String transform(JWTClaimsSet claimsSet) {
				return claimsSet.getSubject();
			}
		};

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject("alice").build();

		assertEquals("alice", claimsSet.toType(transformer));
	}


	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/154/list-of-strings-as-custom-claim-will-add
	public void testParseListOfStrings()
		throws ParseException {

		String json = "{ \"alg\":\"HS256\", \"aud\":[\"a\",\"b\"],\"test\":[\"a\",\"b\"] }";

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(json);

		assertEquals("HS256", claimsSet.getStringClaim(HeaderParameterNames.ALGORITHM));

		List<String> audList = claimsSet.getStringListClaim(JWTClaimNames.AUDIENCE);
		assertEquals("a", audList.get(0));
		assertEquals("b", audList.get(1));
		assertEquals(2, audList.size());

		List<String> testList = claimsSet.getStringListClaim("test");
		assertEquals("a", testList.get(0));
		assertEquals("b", testList.get(1));
		assertEquals(2, testList.size());

		assertEquals(3, claimsSet.getClaims().size());
	}


	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/154/list-of-strings-as-custom-claim-will-add
	public void testListOfStrings() {

		List<String> audList = new LinkedList<>();
		audList.add("a");
		audList.add("b");

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim(JWTClaimNames.AUDIENCE, audList)
			.build();

		assertEquals("{\"aud\":[\"a\",\"b\"]}", claimsSet.toString());
	}


	public void testJSONObjectClaim()
		throws Exception {

		Map<String, Object> actor = new LinkedHashMap<>();
		actor.put(JWTClaimNames.SUBJECT, "claire");
		actor.put(JWTClaimNames.ISSUER, "https://openid.c2id.com");

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("act", actor)
			.build();

		Map<String, Object> out = claimsSet.getJSONObjectClaim("act");
		assertEquals("claire", out.get(JWTClaimNames.SUBJECT));
		assertEquals("https://openid.c2id.com", out.get(JWTClaimNames.ISSUER));
		assertEquals(2, out.size());
	}


	public void testJSONObjectClaim_convertFromMap()
		throws Exception {

		Map<Object,Object> actor = new HashMap<>();
		actor.put(JWTClaimNames.SUBJECT, "claire");
		actor.put(JWTClaimNames.ISSUER, "https://openid.c2id.com");
		actor.put(1, 1000); // must be ignored

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("act", actor)
			.build();

		Map<String, Object> out = claimsSet.getJSONObjectClaim("act");
		assertEquals("claire", out.get(JWTClaimNames.SUBJECT));
		assertEquals("https://openid.c2id.com", out.get(JWTClaimNames.ISSUER));
		assertEquals(2, out.size());
	}


	public void testJSONObjectClaim_Null()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().build();

		assertNull(claimsSet.getJSONObjectClaim("act"));
	}


	public void testJSONObjectClaim_invalidType()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("act", "claire")
			.build();

		try {
			claimsSet.getJSONObjectClaim("act");
			fail();
		} catch (ParseException e) {
			assertEquals("The \"act\" claim is not a JSON object or Map", e.getMessage());
		}
	}

	
	public void testClaimAsJSONObject()
		throws Exception {

		Map<String, Object> jsonObject = new LinkedHashMap<>();
		jsonObject.put("key", "value");
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("prm", jsonObject)
			.build();
		
		jsonObject = claimsSet.getJSONObjectClaim("prm");
		assertEquals("value", jsonObject.get("key"));
		assertEquals(1, jsonObject.size());
		
		Map<String, Object> claimsJSONObject = claimsSet.toJSONObject();
		jsonObject = (Map<String, Object>) claimsJSONObject.get("prm");
		assertEquals("value", jsonObject.get("key"));
		assertEquals(1, jsonObject.size());
		
		JWT plainJWT = new PlainJWT(claimsSet);
		
		String compactEncodedJWT = plainJWT.serialize();
		
		plainJWT = PlainJWT.parse(compactEncodedJWT);
		
		claimsSet = plainJWT.getJWTClaimsSet();
		
		jsonObject = claimsSet.getJSONObjectClaim("prm");
		assertEquals("value", jsonObject.get("key"));
		assertEquals(1, jsonObject.size());
	}
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/236
	public void testGetAudienceFromStringClaim() {
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim(JWTClaimNames.AUDIENCE, "1")
			.build();
		
		assertEquals(Collections.singletonList("1"), claimsSet.getAudience());
	}


	public void testBuilder_serializeNullClaims_true() {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.serializeNullClaims(true)
			.subject("alice")
			.claim("xxx", null)
			.build();

		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		assertEquals("alice", jsonObject.get("sub"));
		assertTrue(jsonObject.containsKey("xxx"));
		assertNull(jsonObject.get("xxx"));
		assertEquals(2, jsonObject.size());

		jsonObject = claimsSet.toJSONObject(true);
		assertEquals("alice", jsonObject.get("sub"));
		assertTrue(jsonObject.containsKey("xxx"));
		assertNull(jsonObject.get("xxx"));
		assertEquals(2, jsonObject.size());

		jsonObject = claimsSet.toJSONObject(false);
		assertEquals("alice", jsonObject.get("sub"));
		assertEquals(1, jsonObject.size());

		assertEquals("{\"sub\":\"alice\",\"xxx\":null}", claimsSet.toPayload().toString());
		assertEquals("{\"sub\":\"alice\",\"xxx\":null}", claimsSet.toPayload(true).toString());
		assertEquals("{\"sub\":\"alice\"}", claimsSet.toPayload(false).toString());

		assertEquals("{\"sub\":\"alice\",\"xxx\":null}", claimsSet.toString());
		assertEquals("{\"sub\":\"alice\",\"xxx\":null}", claimsSet.toString(true));
		assertEquals("{\"sub\":\"alice\"}", claimsSet.toString(false));
	}


	public void testBuilder_serializeNullClaims_false_default() {

		List<JWTClaimsSet> variants = Arrays.asList(
			// false
			new JWTClaimsSet.Builder()
				.serializeNullClaims(false)
				.subject("alice")
				.claim("xxx", null)
				.build(),
			// default
			new JWTClaimsSet.Builder()
				.subject("alice")
				.claim("xxx", null)
				.build()
		);

		for (JWTClaimsSet claimsSet: variants) {

			Map<String, Object> jsonObject = claimsSet.toJSONObject();
			assertEquals("alice", jsonObject.get("sub"));
			assertEquals(1, jsonObject.size());

			jsonObject = claimsSet.toJSONObject(true);
			assertEquals("alice", jsonObject.get("sub"));
			assertTrue(jsonObject.containsKey("xxx"));
			assertNull(jsonObject.get("xxx"));
			assertEquals(2, jsonObject.size());

			jsonObject = claimsSet.toJSONObject(false);
			assertEquals("alice", jsonObject.get("sub"));
			assertEquals(1, jsonObject.size());

			assertEquals("{\"sub\":\"alice\"}", claimsSet.toPayload().toString());
			assertEquals("{\"sub\":\"alice\",\"xxx\":null}", claimsSet.toPayload(true).toString());
			assertEquals("{\"sub\":\"alice\"}", claimsSet.toPayload(false).toString());

			assertEquals("{\"sub\":\"alice\"}", claimsSet.toString());
			assertEquals("{\"sub\":\"alice\",\"xxx\":null}", claimsSet.toString(true));
			assertEquals("{\"sub\":\"alice\"}", claimsSet.toString(false));
		}
	}
	
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/236
	public void testAudienceStringToJSONObject()
		throws Exception {
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim(JWTClaimNames.AUDIENCE, "1")
			.build();
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject();
		assertEquals("1", jsonObject.get(JWTClaimNames.AUDIENCE));
		assertEquals(1, jsonObject.size());
	}
	
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/252/respect-explicit-set-of-null-claims
	public void testToJSONObject_serializeNullClaims()
		throws Exception {
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("myclaim", null)
			.build();
		
		assertNull(claimsSet.getClaim("myclaim"));
		assertTrue(claimsSet.getClaims().containsKey("myclaim"));
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject(true);

		assertTrue(jsonObject.containsKey("myclaim"));
		assertNull(jsonObject.get("myclaim"));
		
		// null claim preserved on parse back
		claimsSet = JWTClaimsSet.parse(JSONObjectUtils.toJSONString(jsonObject));
		
		assertNull(claimsSet.getClaim("myclaim"));
		assertTrue(claimsSet.getClaims().containsKey("myclaim"));
		assertEquals(1, claimsSet.getClaims().size());
	}
	
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/252/respect-explicit-set-of-null-claims
	// audience has special treatment
	public void testToJSONObject_serializeNullClaims_audience()
		throws Exception {
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.audience((String)null)
			.build();
		
		assertTrue(claimsSet.getAudience().isEmpty());
		assertTrue(claimsSet.getClaims().containsKey(JWTClaimNames.AUDIENCE));
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject(true);

		assertTrue(jsonObject.containsKey(JWTClaimNames.AUDIENCE));
		assertNull(jsonObject.get(JWTClaimNames.AUDIENCE));
		
		// null aud claim preserved on parse back
		claimsSet = JWTClaimsSet.parse(JSONObjectUtils.toJSONString(jsonObject));
		
		assertTrue(claimsSet.getAudience().isEmpty());
		assertTrue(claimsSet.getClaims().containsKey(JWTClaimNames.AUDIENCE));
		assertEquals(1, claimsSet.getClaims().size());
	}
	
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/252/respect-explicit-set-of-null-claims
	// audience has special treatment
	public void testToJSONObject_serializeNullClaims_audienceList()
		throws Exception {
		
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.audience((List<String>)null)
			.build();
		
		assertTrue(claimsSet.getAudience().isEmpty());
		assertTrue(claimsSet.getClaims().containsKey(JWTClaimNames.AUDIENCE));
		
		Map<String, Object> jsonObject = claimsSet.toJSONObject(true);

		assertTrue(jsonObject.containsKey(JWTClaimNames.AUDIENCE));
		assertNull(jsonObject.get(JWTClaimNames.AUDIENCE));
		
		// null aud claim preserved on parse back
		claimsSet = JWTClaimsSet.parse(JSONObjectUtils.toJSONString(jsonObject));
		
		assertTrue(claimsSet.getAudience().isEmpty());
		assertTrue(claimsSet.getClaims().containsKey(JWTClaimNames.AUDIENCE));
		assertEquals(1, claimsSet.getClaims().size());
	}
	
	
	public void testAllowNullClaimsInParse() throws ParseException {
		
		String claimsJSON = "{\"sub\": null}";
		
		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(claimsJSON);
		
		assertNull(jwtClaimsSet.getSubject());
		
		assertEquals(1, jwtClaimsSet.getClaims().size());
		
		assertTrue(jwtClaimsSet.getClaims().containsKey(JWTClaimNames.SUBJECT));
	}

	
	public void testEquals() throws ParseException {

		String json = "{\"sub\":\"alice\",\"irt\":true,\"rft\":\"YWxpY2U.aHR0cDovL2NsaWVudDEuZXhhbXBsZS5jb20.rsKHqBpyEh-MMtllO7chHg\",\"aud\":[\"http:\\/\\/userinfo.example.com\"],\"iss\":\"http:\\/\\/oidc.example.com\",\"ate\":\"IDENTIFIER\",\"lng\":true,\"iat\":1420544052,\"cid\":\"http:\\/\\/client1.example.com\"}";
		JWTClaimsSet claimsA = JWTClaimsSet.parse(json);
		JWTClaimsSet claimsB = JWTClaimsSet.parse(json);

		assertEquals(claimsB, claimsA);
	}
	
	
	// https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/462/
	public void testParseNormalizesAudienceToStringArray() throws ParseException {
	
		String json = 
			"{" +
			"    \"iss\": \"my-client\"," +
			"    \"sub\": \"my-client\"," +
			"    \"aud\": \"https://server.example.org\"," +
			"    \"jti\": \"my-jwt-001\"," +
			"    \"exp\": 1744228361," +
			"    \"iat\": 1644228361" +
			"}";
		
		JWTClaimsSet claimsSet = JWTClaimsSet.parse(JSONObjectUtils.parse(json));
		
		try {
			claimsSet.getStringClaim("aud");
			fail();
		} catch (ParseException e) {
			assertEquals("The aud claim is not a String", e.getMessage());
		}
		
		assertEquals(Collections.singletonList("https://server.example.org"), claimsSet.getStringListClaim("aud"));
	}

	public void testParseNormalizesSubjectNumberToString() throws ParseException {

		String claimsJSON = "{\"sub\": 1234}";

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(claimsJSON);

		assertEquals("1234", jwtClaimsSet.getClaim(JWTClaimNames.SUBJECT));
	}

	public void testParseNullIssuer() throws ParseException {

		String claimsJSON = "{\"iss\": null}";

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(claimsJSON);

		assertNull(jwtClaimsSet.getIssuer());
	}

	public void testParseNullSubject() throws ParseException {

		String claimsJSON = "{\"sub\": null}";

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(claimsJSON);

		assertNull(jwtClaimsSet.getSubject());
	}

	public void testParseNullAudience() throws ParseException {

		String claimsJSON = "{\"aud\": null}";

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(claimsJSON);

		assertTrue(jwtClaimsSet.getAudience().isEmpty());
	}

	public void testParseNullExpirationTime() throws ParseException {

		String claimsJSON = "{\"exp\": null}";

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(claimsJSON);

		assertNull(jwtClaimsSet.getExpirationTime());
	}

	public void testParseNullNotBeforeTime() throws ParseException {

		String claimsJSON = "{\"nbf\": null}";

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(claimsJSON);

		assertNull(jwtClaimsSet.getNotBeforeTime());
	}

	public void testParseNullIssueTime() throws ParseException {

		String claimsJSON = "{\"iat\": null}";

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(claimsJSON);

		assertNull(jwtClaimsSet.getIssueTime());
	}

	public void testParseNullJTI() throws ParseException {

		String claimsJSON = "{\"jti\": null}";

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(claimsJSON);

		assertNull(jwtClaimsSet.getJWTID());
	}

	public void testParseNullSome() throws ParseException {

		String claimsJSON = "{\"xxx\": null}";

		JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(claimsJSON);

		assertNull(jwtClaimsSet.getClaim("xxx"));
	}
	
	
	public void testParseBooleanSubject() {
		
		String claimsJSON = "{\"sub\": true}";
		
		try {
			JWTClaimsSet.parse(claimsJSON);
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal sub claim", e.getMessage());
		}
	}
	
	
	public void testParseBooleanAudience() {
		
		String claimsJSON = "{\"aud\": true}";
		
		try {
			JWTClaimsSet.parse(claimsJSON);
			fail();
		} catch (ParseException e) {
			assertEquals("Illegal aud claim", e.getMessage());
		}
	}


	public void testGetListClaim() throws ParseException {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("some_list", Arrays.asList("a", 1, true))
			.build();

		String json = claimsSet.toString();

		claimsSet = JWTClaimsSet.parse(json);

		List<Object> someList = claimsSet.getListClaim("some_list");
		assertEquals("a", someList.get(0));
		assertEquals(1L, someList.get(1));
		assertEquals(true, someList.get(2));
		assertEquals(3, someList.size());
	}


	public void testGetListClaim_none() throws ParseException {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.build();

		String json = claimsSet.toString();

		claimsSet = JWTClaimsSet.parse(json);

		assertNull(claimsSet.getListClaim("some_list"));
	}


	public void testGetListClaim_nullValue() throws ParseException {

		JWTClaimsSet claimsSet = JWTClaimsSet.parse("{\"some_list\":null}");

		assertNull(claimsSet.getListClaim("some_list"));
	}


	public void testCustomDateClaim() throws ParseException {

		Date now = DateUtils.nowWithSecondsPrecision();

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("date-claim-a", now)
			.claim("date-claim-b", now.getTime() / 1000)
			.build();

		String json = claimsSet.toString();

		claimsSet = JWTClaimsSet.parse(json);

		assertEquals(DateUtils.toSecondsSinceEpoch(now), claimsSet.getClaim("date-claim-a"));
		assertEquals(DateUtils.toSecondsSinceEpoch(now), claimsSet.getClaim("date-claim-b"));
	}


	public void testEntityMappingExample() {

		String stringClaim = "string";

		long intClaim = 10L;

		double decimalFractionClaim = 3.14;

		boolean boolClaim = true;

		List<Object> jsonArrayClaim = Arrays.asList((Object) "a", true, 66);

		Map<String, Object> jsonObjectClaim = new HashMap<>();
		jsonObjectClaim.put("member-1", "a");
		jsonObjectClaim.put("member-2", true);
		jsonObjectClaim.put("member-3", 66);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("string", stringClaim)
			.claim("int", intClaim)
			.claim("decimal_fraction", decimalFractionClaim)
			.claim("bool", boolClaim)
			.claim("json_array", jsonArrayClaim)
			.claim("json_object", jsonObjectClaim)
			.build();

		String json = claimsSet.toString();

		System.out.println(json);
	}

	public void testEntityMappingParseExample() throws ParseException {
		
		String json = 
			"{\n" +
			"  \"string\": \"string\"," +
			"  \"bool\": true," +
			"  \"int\": 10," +
			"  \"decimal_fraction\": 3.14," +
			"  \"json_array\": [" +
			"    \"a\"," +
			"    true," +
			"    66" +
			"  ]," +
			"  \"json_object\": {" +
			"    \"member-1\": \"a\"," +
			"    \"member-2\": true," +
			"    \"member-3\": 66" +
			"  }" +
			"}";

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(json);

		String stringClaim = claimsSet.getStringClaim("string");
		Long intClaim = claimsSet.getLongClaim("int");
		Boolean boolClaim = claimsSet.getBooleanClaim("bool");
		Double decimalFractionClaim = claimsSet.getDoubleClaim("decimal_fraction");
		List<Object> jsonArrayClaim = claimsSet.getListClaim("json_array");
		Map<String, Object> jsonObjectClaim = claimsSet.getJSONObjectClaim("json_object");

		assertEquals("string", stringClaim);
		assertEquals(10L, intClaim.longValue());
		assertEquals(3.14, decimalFractionClaim.doubleValue());
		assertTrue(boolClaim);

		assertEquals(Arrays.asList((Object) "a", true, 66L), jsonArrayClaim);

		assertEquals("a", JSONObjectUtils.getString(jsonObjectClaim, "member-1"));
                assertTrue(JSONObjectUtils.getBoolean(jsonObjectClaim, "member-2"));
		assertEquals(66L, JSONObjectUtils.getLong(jsonObjectClaim, "member-3"));
	}


	public void testSerializationWithDeepJSONObjectNestingCausesStackOverflowError() {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("o", createJSONObjectWithNesting(10_000))
			.build();

		try {
			claimsSet.toString();
			fail();
		} catch (StackOverflowError e) {
			assertNull(e.getMessage());
		}
	}


	public void testSerializationWithDeepJSONArrayNestingCausesStackOverflowError() {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.claim("a", createJSONArrayWithNesting(10_000))
			.build();

		try {
			claimsSet.toString();
			fail();
		} catch (StackOverflowError e) {
			assertNull(e.getMessage());
		}
	}


	public void testParseWithExcessiveJSONObjectNesting() {

		JsonReader jsonReader = new JsonReader(new InputStreamReader(new ByteArrayInputStream(new byte[]{})));
		int nestingLimit = jsonReader.getNestingLimit();
		assertEquals(255, nestingLimit);

		Map<String, Object> jsonObject = createJSONObjectWithNesting(nestingLimit);
		String json = JSONObjectUtils.toJSONString(jsonObject);
		try {
			JWTClaimsSet.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON object", e.getMessage());
		}
	}


	public void testParseWithExcessiveJSONArrayNesting() {

		JsonReader jsonReader = new JsonReader(new InputStreamReader(new ByteArrayInputStream(new byte[]{})));
		int nestingLimit = jsonReader.getNestingLimit();
		assertEquals(255, nestingLimit);

		List<Object> jsonArray = createJSONArrayWithNesting(nestingLimit);
		String json = JSONArrayUtils.toJSONString(jsonArray);
		try {
			JWTClaimsSet.parse(json);
			fail();
		} catch (ParseException e) {
			assertEquals("Invalid JSON object", e.getMessage());
		}
	}


	public void testParseWithMaxJSONObjectNesting()
		throws ParseException {

		JsonReader jsonReader = new JsonReader(new InputStreamReader(new ByteArrayInputStream(new byte[]{})));
		int nestingLimit = jsonReader.getNestingLimit();
		assertEquals(255, nestingLimit);

		Map<String, Object> jsonObject = createJSONObjectWithNesting(nestingLimit - 1);
		String json = JSONObjectUtils.toJSONString(jsonObject);
		assertEquals(jsonObject, JWTClaimsSet.parse(json).getClaims());
	}
}
