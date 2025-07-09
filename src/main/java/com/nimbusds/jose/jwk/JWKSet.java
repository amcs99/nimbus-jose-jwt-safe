/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2018, Connect2id Ltd.
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


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.*;
import net.jcip.annotations.Immutable;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.Proxy;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.*;


/**
 * JSON Web Key (JWK) set. Represented by a JSON object that contains an array
 * of {@link JWK JSON Web Keys} (JWKs) as the value of its "keys" member.
 * Additional (custom) members of the JWK Set JSON object are also supported.
 *
 * <p>Example JWK set:
 *
 * <pre>
 * {
 *   "keys" : [ { "kty" : "EC",
 *                "crv" : "P-256",
 *                "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *                "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *                "use" : "enc",
 *                "kid" : "1" },
 *
 *              { "kty" : "RSA",
 *                "n"   : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 *                         4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
 *                         tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
 *                         QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
 *                         SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
 *                         w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *                "e"   : "AQAB",
 *                "alg" : "RS256",
 *                "kid" : "2011-04-29" } ]
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @author Vedran Pavic
 * @version 2024-03-17
 */
@Immutable
public class JWKSet implements Serializable {
	
	
	private static final long serialVersionUID = 1L;


	/**
	 * The MIME type of JWK set objects: 
	 * {@code application/jwk-set+json; charset=UTF-8}
	 */
	public static final String MIME_TYPE = "application/jwk-set+json; charset=UTF-8";


	/**
	 * The JWK list.
	 */
	private final List<JWK> keys;


	/**
	 * Additional custom members.
	 */
	private final Map<String,Object> customMembers;


	/**
	 * Creates a new empty JWK set.
	 */
	public JWKSet() {

		this(Collections.<JWK>emptyList());
	}


	/**
	 * Creates a new JWK set with a single key.
	 *
	 * @param key The JWK. Must not be {@code null}.
	 */
	public JWKSet(final JWK key) {
		
		this(Collections.singletonList(Objects.requireNonNull(key, "The JWK must not be null")));
	}


	/**
	 * Creates a new JWK set with the specified keys.
	 *
	 * @param keys The JWK list. Must not be {@code null}.
	 */
	public JWKSet(final List<JWK> keys) {

		this(keys, Collections.<String, Object>emptyMap());
	}


	/**
	 * Creates a new JWK set with the specified keys and additional custom
	 * members.
	 *
	 * @param keys          The JWK list. Must not be {@code null}.
	 * @param customMembers The additional custom members. Must not be
	 *                      {@code null}.
	 */
	public JWKSet(final List<JWK> keys, final Map<String,Object> customMembers) {

		this.keys = Collections.unmodifiableList(Objects.requireNonNull(keys, "The JWK list must not be null"));
		this.customMembers = Collections.unmodifiableMap(customMembers);
	}


	/**
	 * Returns the keys (ordered) of this JWK set.
	 *
	 * @return The keys as an unmodifiable list, empty list if none.
	 */
	public List<JWK> getKeys() {

		return keys;
	}
	
	
	/**
	 * Returns {@code true} if this JWK set is empty.
	 *
	 * @return {@code true} if empty, else {@code false}.
	 */
	public boolean isEmpty() {
		return keys.isEmpty();
	}
	
	
	/**
	 * Returns the number of keys in this JWK set.
	 *
	 * @return The number of keys, zero if none.
	 */
	public int size() {
		return keys.size();
	}
	
	
	/**
	 * Returns the key from this JWK set as identified by its Key ID (kid)
	 * member.
	 *
	 * <p>If more than one key exists in the JWK Set with the same
	 * identifier, this function returns only the first one in the set.
	 *
	 * @param kid They key identifier.
	 *
	 * @return The key identified by {@code kid} or {@code null} if no key
	 *         exists.
	 */
	public JWK getKeyByKeyId(String kid) {
		
		for (JWK key : getKeys()) {
	        
	        	if (key.getKeyID() != null && key.getKeyID().equals(kid)) {
	        		return key;
	        	}
        	}
		
		// no key found
		return null;
	}
	
	
	/**
	 * Returns {@code true} if this JWK set contains the specified JWK as
	 * public or private key, by comparing its thumbprint with those of the
	 * keys in the set.
	 *
	 * @param jwk The JWK to check. Must not be {@code null}.
	 *
	 * @return {@code true} if contained, {@code false} if not.
	 *
	 * @throws JOSEException If thumbprint computation failed.
	 */
	public boolean containsJWK(final JWK jwk) throws JOSEException {
		
		Base64URL thumbprint = jwk.computeThumbprint();
		
		for (JWK k: getKeys()) {
			if (thumbprint.equals(k.computeThumbprint())) {
				return true; // found
			}
		}
		return false;
	}
	
	
	/**
	 * Returns the additional custom members of this (JWK) set.
	 *
	 * @return The additional custom members as an unmodifiable map, empty
	 *         map if none.
	 */
	public Map<String,Object> getAdditionalMembers() {

		return customMembers;
	}
	
	
	/**
	 * Returns a copy of this (JWK) set with all private keys and
	 * parameters removed.
	 *
	 * @return A copy of this JWK set with all private keys and parameters
	 *         removed.
	 */
	public JWKSet toPublicJWKSet() {

		List<JWK> publicKeyList = new LinkedList<>();

		for (JWK key: keys) {

			JWK publicKey = key.toPublicJWK();

			if (publicKey != null) {
				publicKeyList.add(publicKey);
			}
		}

		return new JWKSet(publicKeyList, customMembers);
	}


	/**
	 * Filters the keys in this JWK set.
	 *
	 * @param jwkMatcher The JWK matcher to filter the keys. Must not be
	 *                   {@code null}.
	 *
	 * @return The new filtered JWK set.
	 */
	public JWKSet filter(final JWKMatcher jwkMatcher) {

		List<JWK> matches = new LinkedList<>();

		for (JWK key: keys) {
			if (jwkMatcher.matches(key)) {
				matches.add(key);
			}
		}

		return new JWKSet(matches, customMembers);
	}


	/**
	 * Returns {@code true} if this JWK set contains non-public keys.
	 *
	 * @return {@code true} if non-public keys are found, {@code false} if
	 *         there are only public keys in the JWK set.
	 */
	public boolean containsNonPublicKeys() {

		for (JWK jwk: getKeys()) {
			if (jwk.isPrivate()) {
				return true;
			}
		}
		return false;
	}
	
	
	/**
	 * Returns the JSON object representation of this JWK set. Only public
	 * keys will be included. Use the alternative
	 * {@link #toJSONObject(boolean)} method to include all key material.
	 *
	 * @return The JSON object representation.
	 */
	public Map<String, Object> toJSONObject() {

		return toJSONObject(true);
	}
	
	
	/**
	 * Returns the JSON object representation of this JWK set.
	 *
	 * @param publicKeysOnly Controls the inclusion of private keys and
	 *                       parameters into the output JWK members. If
	 *                       {@code true} only public keys will be
	 *                       included. If {@code false} all available keys
	 *                       with their parameters will be included.
	 *
	 * @return The JSON object representation.
	 */
	public Map<String, Object> toJSONObject(final boolean publicKeysOnly) {

		Map<String, Object> o = JSONObjectUtils.newJSONObject();
		o.putAll(customMembers);
		List<Object> a = JSONArrayUtils.newJSONArray();

		for (JWK key: keys) {

			if (publicKeysOnly) {

				// Try to get public key, then serialise
				JWK publicKey = key.toPublicJWK();

				if (publicKey != null) {
					a.add(publicKey.toJSONObject());
				}
			} else {

				a.add(key.toJSONObject());
			}
		}

		o.put("keys", a);

		return o;
	}
	
	
	/**
	 * Returns the JSON object string representation of this JWK set.
	 *
	 * @param publicKeysOnly Controls the inclusion of private keys and
	 *                       parameters into the output JWK members. If
	 *                       {@code true} only public keys will be
	 *                       included. If {@code false} all available keys
	 *                       with their parameters will be included.
	 *
	 * @return The JSON object string representation.
	 */
	public String toString(final boolean publicKeysOnly) {

		return JSONObjectUtils.toJSONString(toJSONObject(publicKeysOnly));
	}
	
	
	/**
	 * Returns the JSON object string representation of this JWK set. Only
	 * public keys will be included. Use the alternative
	 * {@link #toString(boolean)} method to include all key material.
	 *
	 * @return The JSON object string representation. Only public keys will
	 *         be included.
	 */
	@Override
	public String toString() {

		return toString(true);
	}
	
	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof JWKSet)) return false;
		JWKSet jwkSet = (JWKSet) o;
		return getKeys().equals(jwkSet.getKeys()) && customMembers.equals(jwkSet.customMembers);
	}
	
	
	@Override
	public int hashCode() {
		return Objects.hash(getKeys(), customMembers);
	}
	
	
	/**
	 * Parses the specified string representing a JWK set.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The JWK set.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid
	 *                        JWK set.
	 */
	public static JWKSet parse(final String s)
		throws ParseException {

		return parse(JSONObjectUtils.parse(s));
	}
	
	
	/**
	 * Parses the specified JSON object representing a JWK set.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The JWK set.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid
	 *                        JWK set.
	 */
	public static JWKSet parse(final Map<String, Object> json)
		throws ParseException {

		List<Object> keyArray = JSONObjectUtils.getJSONArray(json, "keys");
		
		if (keyArray == null) {
			throw new ParseException("Missing required \"keys\" member", 0);
		}

		List<JWK> keys = new LinkedList<>();

		for (int i=0; i < keyArray.size(); i++) {

			try {
				Map<String, Object> keyJSONObject = (Map<String, Object>)keyArray.get(i);
				keys.add(JWK.parse(keyJSONObject));
				
			} catch (ClassCastException e) {
				
				throw new ParseException("The \"keys\" JSON array must contain JSON objects only", 0);
				
			} catch (ParseException e) {
				
				if (e.getMessage() != null && e.getMessage().startsWith("Unsupported key type")) {
					// Ignore unknown key type
					// https://tools.ietf.org/html/rfc7517#section-5
					continue;
				}

				throw new ParseException("Invalid JWK at position " + i + ": " + e.getMessage(), 0);
			}
		}

		// Parse additional custom members
		Map<String, Object> additionalMembers = new HashMap<>();
		for (Map.Entry<String,Object> entry: json.entrySet()) {
			
			if (entry.getKey() == null || entry.getKey().equals("keys")) {
				continue;
			}
			
			additionalMembers.put(entry.getKey(), entry.getValue());
		}
		
		return new JWKSet(keys, additionalMembers);
	}
	
	
	/**
	 * Loads a JWK set from the specified input stream.
	 *
	 * @param inputStream The JWK set input stream. Must not be {@code null}.
	 *
	 * @return The JWK set.
	 *
	 * @throws IOException    If the input stream couldn't be read.
	 * @throws ParseException If the input stream couldn't be parsed to a
	 *                        valid JWK set.
	 */
	public static JWKSet load(final InputStream inputStream)
		throws IOException, ParseException {

		return parse(IOUtils.readInputStreamToString(inputStream, StandardCharset.UTF_8));
	}
	
	
	/**
	 * Loads a JWK set from the specified file.
	 *
	 * @param file The JWK set file. Must not be {@code null}.
	 *
	 * @return The JWK set.
	 *
	 * @throws IOException    If the file couldn't be read.
	 * @throws ParseException If the file couldn't be parsed to a valid JWK
	 *                        set.
	 */
	public static JWKSet load(final File file)
		throws IOException, ParseException {

		return parse(IOUtils.readFileToString(file, StandardCharset.UTF_8));
	}
	
	
	/**
	 * Loads a JWK set from the specified URL.
	 *
	 * @param url            The JWK set URL. Must not be {@code null}.
	 * @param connectTimeout The URL connection timeout, in milliseconds.
	 *                       If zero no (infinite) timeout.
	 * @param readTimeout    The URL read timeout, in milliseconds. If zero
	 *                       no (infinite) timeout.
	 * @param sizeLimit      The read size limit, in bytes. If zero no
	 *                       limit.
	 *
	 * @return The JWK set.
	 *
	 * @throws IOException    If the file couldn't be read.
	 * @throws ParseException If the file couldn't be parsed to a valid JWK
	 *                        set.
	 */
	public static JWKSet load(final URL url,
				  final int connectTimeout,
				  final int readTimeout,
				  final int sizeLimit)
		throws IOException, ParseException {

		return load(url, connectTimeout, readTimeout, sizeLimit, null);
	}
	
	
	/**
	 * Loads a JWK set from the specified URL.
	 *
	 * @param url            The JWK set URL. Must not be {@code null}.
	 * @param connectTimeout The URL connection timeout, in milliseconds.
	 *                       If zero no (infinite) timeout.
	 * @param readTimeout    The URL read timeout, in milliseconds. If zero
	 *                       no (infinite) timeout.
	 * @param sizeLimit      The read size limit, in bytes. If zero no
	 *                       limit.
	 * @param proxy	         The optional proxy to use when opening the
	 *                       connection to retrieve the resource. If
	 *                       {@code null}, no proxy is used.
	 *
	 * @return The JWK set.
	 *
	 * @throws IOException    If the file couldn't be read.
	 * @throws ParseException If the file couldn't be parsed to a valid JWK
	 *                        set.
	 */
	public static JWKSet load(final URL url,
				  final int connectTimeout,
				  final int readTimeout,
				  final int sizeLimit,
				  final Proxy proxy)
			throws IOException, ParseException {

		DefaultResourceRetriever resourceRetriever = new DefaultResourceRetriever(
				connectTimeout,
				readTimeout,
				sizeLimit);
		resourceRetriever.setProxy(proxy);
		Resource resource = resourceRetriever.retrieveResource(url);
		return parse(resource.getContent());
	}
	
	
	/**
	 * Loads a JWK set from the specified URL.
	 *
	 * @param url The JWK set URL. Must not be {@code null}.
	 *
	 * @return The JWK set.
	 *
	 * @throws IOException    If the file couldn't be read.
	 * @throws ParseException If the file couldn't be parsed to a valid JWK
	 *                        set.
	 */
	public static JWKSet load(final URL url)
		throws IOException, ParseException {

		return load(url, 0, 0, 0);
	}
	
	
	/**
	 * Loads a JWK set from the specified JCA key store. Key
	 * conversion exceptions are silently swallowed. PKCS#11 stores are
	 * also supported. Requires BouncyCastle.
	 *
	 * <p><strong>Important:</strong> The X.509 certificates are not
	 * validated!
	 *
	 * @param keyStore The key store. Must not be {@code null}.
	 * @param pwLookup The password lookup for password-protected keys,
	 *                 {@code null} if not specified.
	 *
	 * @return The JWK set, empty if no keys were loaded.
	 *
	 * @throws KeyStoreException On a key store exception.
	 */
	public static JWKSet load(final KeyStore keyStore, final PasswordLookup pwLookup)
		throws KeyStoreException {
		
		List<JWK> jwks = new LinkedList<>();
		
		// Load RSA and EC keys
		for (Enumeration<String> keyAliases = keyStore.aliases(); keyAliases.hasMoreElements(); ) {
			
			final String keyAlias = keyAliases.nextElement();
			final char[] keyPassword = pwLookup == null ? "".toCharArray() : pwLookup.lookupPassword(keyAlias);
			
			Certificate cert = keyStore.getCertificate(keyAlias);
			if (cert == null) {
				continue; // skip
			}
			
			if (cert.getPublicKey() instanceof RSAPublicKey) {
				
				RSAKey rsaJWK;
				try {
					rsaJWK = RSAKey.load(keyStore, keyAlias, keyPassword);
				} catch (JOSEException e) {
					continue; // skip cert
				}
				
				if (rsaJWK == null) {
					continue; // skip key
				}
				
				jwks.add(rsaJWK);
				
			} else if (cert.getPublicKey() instanceof ECPublicKey) {
				
				ECKey ecJWK;
				try {
					ecJWK = ECKey.load(keyStore, keyAlias, keyPassword);
				} catch (JOSEException e) {
					continue; // skip cert
				}
				
				if (ecJWK != null) {
					jwks.add(ecJWK);
				}
			}
		}
		
		
		// Load symmetric keys
		for (Enumeration<String> keyAliases = keyStore.aliases(); keyAliases.hasMoreElements(); ) {
			
			final String keyAlias = keyAliases.nextElement();
			final char[] keyPassword = pwLookup == null ? "".toCharArray() : pwLookup.lookupPassword(keyAlias);
			
			OctetSequenceKey octJWK;
			try {
				octJWK = OctetSequenceKey.load(keyStore, keyAlias, keyPassword);
			} catch (JOSEException e) {
				continue; // skip key
			}
			
			if (octJWK != null) {
				jwks.add(octJWK);
			}
		}
		
		return new JWKSet(jwks);
	}
}
