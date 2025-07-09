/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2024, Connect2id Ltd.
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


import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.*;
import net.jcip.annotations.Immutable;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.security.*;
import java.text.ParseException;
import java.util.*;


/**
 * {@link KeyType#OCT Octet sequence} JSON Web Key (JWK), used to represent
 * symmetric keys. This class is immutable.
 *
 * <p>Octet sequence JWKs should specify the algorithm intended to be used with
 * the key, unless the application uses other means or convention to determine
 * the algorithm used.
 *
 * <p>Example JSON object representation of an octet sequence JWK:
 *
 * <pre>
 * {
 *   "kty" : "oct",
 *   "alg" : "A128KW",
 *   "k"   : "GawgguFyGrWKav7AX4VKUg"
 * }
 * </pre>
 *
 * <p>Use the builder to create a new octet JWK:
 *
 * <pre>
 * OctetSequenceKey key = new OctetSequenceKey.Builder(bytes)
 * 	.keyID("123")
 * 	.build();
 * </pre>
 * 
 * @author Justin Richer
 * @author Vladimir Dzhuvinov
 * @version 2024-10-31
 */
@Immutable
public final class OctetSequenceKey extends JWK implements SecretJWK {


	private static final long serialVersionUID = 1L;


	/**
	 * The key value.
	 */
	private final Base64URL k;


	/**
	 * Builder for constructing octet sequence JWKs.
	 *
	 * <p>Example usage:
	 *
	 * <pre>
	 * OctetSequenceKey key = new OctetSequenceKey.Builder(k)
	 *     .algorithm(JWSAlgorithm.HS512)
	 *     .keyID("123")
	 *     .build();
	 * </pre>
	 */
	public static class Builder {


		/**
		 * The key value.
		 */
		private final Base64URL k;


		/**
		 * The public key use, optional.
		 */
		private KeyUse use;


		/**
		 * The key operations, optional.
		 */
		private Set<KeyOperation> ops;


		/**
		 * The intended JOSE algorithm for the key, optional.
		 */
		private Algorithm alg;


		/**
		 * The key ID, optional.
		 */
		private String kid;


		/**
		 * X.509 certificate URL, optional.
		 */
		private URI x5u;


		/**
		 * X.509 certificate SHA-1 thumbprint, optional.
		 */
		@Deprecated
		private Base64URL x5t;
		
		
		/**
		 * X.509 certificate SHA-256 thumbprint, optional.
		 */
		private Base64URL x5t256;


		/**
		 * The X.509 certificate chain, optional.
		 */
		private List<Base64> x5c;
		
		
		/**
		 * The key expiration time, optional.
		 */
		private Date exp;
		
		
		/**
		 * The key not-before time, optional.
		 */
		private Date nbf;
		
		
		/**
		 * The key issued-at time, optional.
		 */
		private Date iat;


		/**
		 * The key revocation, optional.
		 */
		private KeyRevocation revocation;
		
		
		/**
		 * Reference to the underlying key store, {@code null} if none.
		 */
		private KeyStore ks;


		/**
		 * Creates a new octet sequence JWK builder.
		 *
		 * @param k The key value. It is represented as the Base64URL 
		 *          encoding of value's big endian representation. Must
		 *          not be {@code null}.
		 */
		public Builder(final Base64URL k) {

			this.k = Objects.requireNonNull(k);
		}


		/**
		 * Creates a new octet sequence JWK builder.
		 *
		 * @param key The key value. Must not be empty byte array or
		 *            {@code null}.
		 */
		public Builder(final byte[] key) {

			this(Base64URL.encode(key));

			if (key.length == 0) {
				throw new IllegalArgumentException("The key must have a positive length");
			}
		}


		/**
		 * Creates a new octet sequence JWK builder.
		 *
		 * @param secretKey The secret key to represent. Must not be
		 *                  {@code null}.
		 */
		public Builder(final SecretKey secretKey) {

			this(secretKey.getEncoded());
		}
		
		
		/**
		 * Creates a new octet sequence JWK builder.
		 *
		 * @param octJWK The octet sequence JWK to start with. Must not
		 *               be {@code null}.
		 */
		public Builder(final OctetSequenceKey octJWK) {
			
			k = octJWK.k;
			use = octJWK.getKeyUse();
			ops = octJWK.getKeyOperations();
			alg = octJWK.getAlgorithm();
			kid = octJWK.getKeyID();
			x5u = octJWK.getX509CertURL();
			x5t = octJWK.getX509CertThumbprint();
			x5t256 = octJWK.getX509CertSHA256Thumbprint();
			x5c = octJWK.getX509CertChain();
			exp = octJWK.getExpirationTime();
			nbf = octJWK.getNotBeforeTime();
			iat = octJWK.getIssueTime();
			revocation = octJWK.getKeyRevocation();
			ks = octJWK.getKeyStore();
		}


		/**
		 * Sets the use ({@code use}) of the JWK.
		 *
		 * @param use The key use, {@code null} if not specified or if
		 *            the key is intended for signing as well as
		 *            encryption.
		 *
		 * @return This builder.
		 */
		public Builder keyUse(final KeyUse use) {

			this.use = use;
			return this;
		}


		/**
		 * Sets the operations ({@code key_ops}) of the JWK (for a
		 * non-public key).
		 *
		 * @param ops The key operations, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder keyOperations(final Set<KeyOperation> ops) {

			this.ops = ops;
			return this;
		}


		/**
		 * Sets the intended JOSE algorithm ({@code alg}) for the JWK.
		 *
		 * @param alg The intended JOSE algorithm, {@code null} if not 
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder algorithm(final Algorithm alg) {

			this.alg = alg;
			return this;
		}

		/**
		 * Sets the ID ({@code kid}) of the JWK. The key ID can be used 
		 * to match a specific key. This can be used, for instance, to 
		 * choose a key within a {@link JWKSet} during key rollover. 
		 * The key ID may also correspond to a JWS/JWE {@code kid} 
		 * header parameter value.
		 *
		 * @param kid The key ID, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder keyID(final String kid) {

			this.kid = kid;
			return this;
		}


		/**
		 * Sets the ID ({@code kid}) of the JWK to its SHA-256 JWK
		 * thumbprint (RFC 7638). The key ID can be used to match a
		 * specific key. This can be used, for instance, to choose a
		 * key within a {@link JWKSet} during key rollover. The key ID
		 * may also correspond to a JWS/JWE {@code kid} header
		 * parameter value.
		 *
		 * @return This builder.
		 *
		 * @throws JOSEException If the SHA-256 hash algorithm is not
		 *                       supported.
		 */
		public Builder keyIDFromThumbprint()
			throws JOSEException {

			return keyIDFromThumbprint("SHA-256");
		}


		/**
		 * Sets the ID ({@code kid}) of the JWK to its JWK thumbprint
		 * (RFC 7638). The key ID can be used to match a specific key.
		 * This can be used, for instance, to choose a key within a
		 * {@link JWKSet} during key rollover. The key ID may also
		 * correspond to a JWS/JWE {@code kid} header parameter value.
		 *
		 * @param hashAlg The hash algorithm for the JWK thumbprint
		 *                computation. Must not be {@code null}.
		 *
		 * @return This builder.
		 *
		 * @throws JOSEException If the hash algorithm is not
		 *                       supported.
		 */
		public Builder keyIDFromThumbprint(final String hashAlg)
			throws JOSEException {

			// Put mandatory params in sorted order
			LinkedHashMap<String,String> requiredParams = new LinkedHashMap<>();
			requiredParams.put(JWKParameterNames.OCT_KEY_VALUE, k.toString());
			requiredParams.put(JWKParameterNames.KEY_TYPE, KeyType.OCT.getValue());
			this.kid = ThumbprintUtils.compute(hashAlg, requiredParams).toString();
			return this;
		}


		/**
		 * Sets the X.509 certificate URL ({@code x5u}) of the JWK.
		 *
		 * @param x5u The X.509 certificate URL, {@code null} if not 
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder x509CertURL(final URI x5u) {

			this.x5u = x5u;
			return this;
		}
		
		
		/**
		 * Sets the X.509 certificate SHA-1 thumbprint ({@code x5t}) of
		 * the JWK.
		 *
		 * @param x5t The X.509 certificate SHA-1 thumbprint,
		 *            {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		@Deprecated
		public Builder x509CertThumbprint(final Base64URL x5t) {
			
			this.x5t = x5t;
			return this;
		}
		
		
		/**
		 * Sets the X.509 certificate SHA-256 thumbprint
		 * ({@code x5t#S256}) of the JWK.
		 *
		 * @param x5t256 The X.509 certificate SHA-256 thumbprint,
		 *               {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder x509CertSHA256Thumbprint(final Base64URL x5t256) {
			
			this.x5t256 = x5t256;
			return this;
		}
		

		/**
		 * Sets the X.509 certificate chain ({@code x5c}) of the JWK.
		 *
		 * @param x5c The X.509 certificate chain as a unmodifiable 
		 *            list, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder x509CertChain(final List<Base64> x5c) {

			this.x5c = x5c;
			return this;
		}
		
		
		/**
		 * Sets the expiration time ({@code exp}) of the JWK.
		 *
		 * @param exp The expiration time, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder expirationTime(final Date exp) {
			
			this.exp = exp;
			return this;
		}
		
		
		/**
		 * Sets the not-before time ({@code nbf}) of the JWK.
		 *
		 * @param nbf The not-before time, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder notBeforeTime(final Date nbf) {
			
			this.nbf = nbf;
			return this;
		}
		
		
		/**
		 * Sets the issued-at time ({@code iat}) of the JWK.
		 *
		 * @param iat The issued-at time, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder issueTime(final Date iat) {
			
			this.iat = iat;
			return this;
		}


		/**
		 * Sets the revocation ({@code revoked}) of the JWK.
		 *
		 * @param revocation The key revocation, {@code null} if not
		 *                   specified.
		 *
		 * @return This builder.
		 */
		public Builder keyRevocation(final KeyRevocation revocation) {

			this.revocation = revocation;
			return this;
		}
		
		
		/**
		 * Sets the underlying key store.
		 *
		 * @param keyStore Reference to the underlying key store,
		 *                 {@code null} if none.
		 *
		 * @return This builder.
		 */
		public Builder keyStore(final KeyStore keyStore) {
			
			this.ks = keyStore;
			return this;
		}
		

		/**
		 * Builds a new octet sequence JWK.
		 *
		 * @return The octet sequence JWK.
		 *
		 * @throws IllegalStateException If the JWK parameters were
		 *                               inconsistently specified.
		 */
		public OctetSequenceKey build() {

			try {
				return new OctetSequenceKey(k, use, ops, alg, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, revocation, ks);

			} catch (IllegalArgumentException e) {

				throw new IllegalStateException(e.getMessage(), e);
			}
		}
	}

	
	/**
	 * Creates a new octet sequence JSON Web Key (JWK) with the specified
	 * parameters.
	 *
	 * @param k      The key value. It is represented as the Base64URL
	 *               encoding of the value's big endian representation.
	 *               Must not be {@code null}.
	 * @param use    The key use, {@code null} if not specified or if the
	 *               key is intended for signing as well as encryption.
	 * @param ops    The key operations, {@code null} if not specified.
	 * @param alg    The intended JOSE algorithm for the key, {@code null}
	 *               if not specified.
	 * @param kid    The key ID. {@code null} if not specified.
	 * @param x5u    The X.509 certificate URL, {@code null} if not specified.
	 * @param x5t    The X.509 certificate SHA-1 thumbprint, {@code null}
	 *               if not specified.
	 * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
	 *               if not specified.
	 * @param x5c    The X.509 certificate chain, {@code null} if not
	 *               specified.
	 * @param ks     Reference to the underlying key store, {@code null} if
	 *               not specified.
	 */
	@Deprecated
	public OctetSequenceKey(final Base64URL k,
				final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
		                final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
				final KeyStore ks) {
	
		this(k, use, ops, alg, kid, x5u, x5t, x5t256, x5c, null, null, null, ks);
	}

	
	/**
	 * Creates a new octet sequence JSON Web Key (JWK) with the specified
	 * parameters.
	 *
	 * @param k      The key value. It is represented as the Base64URL
	 *               encoding of the value's big endian representation.
	 *               Must not be {@code null}.
	 * @param use    The key use, {@code null} if not specified or if the
	 *               key is intended for signing as well as encryption.
	 * @param ops    The key operations, {@code null} if not specified.
	 * @param alg    The intended JOSE algorithm for the key, {@code null}
	 *               if not specified.
	 * @param kid    The key ID. {@code null} if not specified.
	 * @param x5u    The X.509 certificate URL, {@code null} if not specified.
	 * @param x5t    The X.509 certificate SHA-1 thumbprint, {@code null}
	 *               if not specified.
	 * @param x5t256 The X.509 certificate SHA-256 thumbprint, {@code null}
	 *               if not specified.
	 * @param x5c    The X.509 certificate chain, {@code null} if not
	 *               specified.
	 * @param exp    The key expiration time, {@code null} if not
	 *               specified.
	 * @param nbf    The key not-before time, {@code null} if not
	 *               specified.
	 * @param iat    The key issued-at time, {@code null} if not specified.
	 * @param ks     Reference to the underlying key store, {@code null} if
	 *               not specified.
	 */
	@Deprecated
	public OctetSequenceKey(final Base64URL k,
				final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
		                final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
				final Date exp, final Date nbf, final Date iat,
				final KeyStore ks) {
	
		this(k, use, ops, alg, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, null, ks);
	}


	/**
	 * Creates a new octet sequence JSON Web Key (JWK) with the specified
	 * parameters.
	 *
	 * @param k          The key value. It is represented as the Base64URL
	 *                   encoding of the value's big endian representation.
	 *                   Must not be {@code null}.
	 * @param use        The key use, {@code null} if not specified or if
	 *                   the key is intended for signing as well as
	 *                   encryption.
	 * @param ops        The key operations, {@code null} if not specified.
	 * @param alg        The intended JOSE algorithm for the key,
	 *                   {@code null} if not specified.
	 * @param kid        The key ID. {@code null} if not specified.
	 * @param x5u        The X.509 certificate URL, {@code null} if not
	 *                   specified.
	 * @param x5t        The X.509 certificate SHA-1 thumbprint,
	 *                   {@code null} if not specified.
	 * @param x5t256     The X.509 certificate SHA-256 thumbprint,
	 *                   {@code null} if not specified.
	 * @param x5c        The X.509 certificate chain, {@code null} if not
	 *                   specified.
	 * @param exp        The key expiration time, {@code null} if not
	 *                   specified.
	 * @param nbf        The key not-before time, {@code null} if not
	 *                   specified.
	 * @param iat        The key issued-at time, {@code null} if not
	 *                   specified.
	 * @param revocation The key revocation, {@code null} if not specified.
	 * @param ks         Reference to the underlying key store,
	 *                   {@code null} if not specified.
	 */
	public OctetSequenceKey(final Base64URL k,
				final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
		                final URI x5u, final Base64URL x5t, final Base64URL x5t256, final List<Base64> x5c,
				final Date exp, final Date nbf, final Date iat, final KeyRevocation revocation,
				final KeyStore ks) {

		super(KeyType.OCT, use, ops, alg, kid, x5u, x5t, x5t256, x5c, exp, nbf, iat, revocation, ks);
		this.k = Objects.requireNonNull(k, "The key value must not be null");
	}
    

	/**
	 * Returns the value of this octet sequence key. 
	 *
	 * @return The key value. It is represented as the Base64URL encoding
	 *         of the value's big endian representation.
	 */
	public Base64URL getKeyValue() {

		return k;
	}
	
	
	/**
	 * Returns a copy of this octet sequence key value as a byte array.
	 * 
	 * @return The key value as a byte array.
	 */
	public byte[] toByteArray() {

		return getKeyValue().decode();
	}


	/**
	 * Returns a secret key representation of this octet sequence key.
	 *
	 * @return The secret key representation, with an algorithm set to
	 *         {@code NONE}.
	 */
	@Override
	public SecretKey toSecretKey() {

		return toSecretKey("NONE");
	}


	/**
	 * Returns a secret key representation of this octet sequence key with
	 * the specified Java Cryptography Architecture (JCA) algorithm.
	 *
	 * @param jcaAlg The JCA algorithm. Must not be {@code null}.
	 *
	 * @return The secret key representation.
	 */
	public SecretKey toSecretKey(final String jcaAlg) {

		return new SecretKeySpec(toByteArray(), jcaAlg);
	}


	@Override
	public LinkedHashMap<String,?> getRequiredParams() {

		// Put mandatory params in sorted order
		LinkedHashMap<String,String> requiredParams = new LinkedHashMap<>();
		requiredParams.put(JWKParameterNames.OCT_KEY_VALUE, k.toString());
		requiredParams.put(JWKParameterNames.KEY_TYPE, getKeyType().toString());
		return requiredParams;
	}


	/**
	 * Octet sequence (symmetric) keys are never considered public, this 
	 * method always returns {@code true}.
	 *
	 * @return {@code true}
	 */
	@Override
	public boolean isPrivate() {

		return true;
	}


	/**
	 * Octet sequence (symmetric) keys are never considered public, this 
	 * method always returns {@code null}.
	 *
	 * @return {@code null}
	 */
	@Override
	public OctetSequenceKey toPublicJWK() {

		return null;
	}


	@Override
	public OctetSequenceKey toRevokedJWK(final KeyRevocation keyRevocation) {

		if (getKeyRevocation() != null) {
			throw new IllegalStateException("Already revoked");
		}

		return new OctetSequenceKey.Builder(this)
			.keyRevocation(Objects.requireNonNull(keyRevocation))
			.build();
	}


	@Override
	public int size() {

		try {
			return ByteUtils.safeBitLength(k.decode());
		} catch (IntegerOverflowException e) {
			throw new ArithmeticException(e.getMessage());
		}
	}


	@Override
	public Map<String, Object> toJSONObject() {

		Map<String, Object> o = super.toJSONObject();

		// Append key value
		o.put(JWKParameterNames.OCT_KEY_VALUE, k.toString());
		
		return o;
	}


	/**
	 * Parses an octet sequence JWK from the specified JSON object string 
	 * representation.
	 *
	 * @param s The JSON object string to parse. Must not be {@code null}.
	 *
	 * @return The octet sequence JWK.
	 *
	 * @throws ParseException If the string couldn't be parsed to an octet
	 *                        sequence JWK.
	 */
	public static OctetSequenceKey parse(final String s)
		throws ParseException {

		return parse(JSONObjectUtils.parse(s));
	}

	
	/**
	 * Parses an octet sequence JWK from the specified JSON object 
	 * representation.
	 *
	 * @param jsonObject The JSON object to parse. Must not be 
	 *                   {@code null}.
	 *
	 * @return The octet sequence JWK.
	 *
	 * @throws ParseException If the JSON object couldn't be parsed to an
	 *                        octet sequence JWK.
	 */
	public static OctetSequenceKey parse(final Map<String, Object> jsonObject) 
		throws ParseException {
		
		// Check the key type
		if (! KeyType.OCT.equals(JWKMetadata.parseKeyType(jsonObject))) {
			throw new ParseException("The key type " + JWKParameterNames.KEY_TYPE + " must be " + KeyType.OCT.getValue(), 0);
		}

		// Parse the mandatory parameter
		Base64URL k = JSONObjectUtils.getBase64URL(jsonObject, JWKParameterNames.OCT_KEY_VALUE);

		try {
			return new OctetSequenceKey(k,
				JWKMetadata.parseKeyUse(jsonObject),
				JWKMetadata.parseKeyOperations(jsonObject),
				JWKMetadata.parseAlgorithm(jsonObject),
				JWKMetadata.parseKeyID(jsonObject),
				JWKMetadata.parseX509CertURL(jsonObject),
				JWKMetadata.parseX509CertThumbprint(jsonObject),
				JWKMetadata.parseX509CertSHA256Thumbprint(jsonObject),
				JWKMetadata.parseX509CertChain(jsonObject),
				JWKMetadata.parseExpirationTime(jsonObject),
				JWKMetadata.parseNotBeforeTime(jsonObject),
				JWKMetadata.parseIssueTime(jsonObject),
				JWKMetadata.parseKeyRevocation(jsonObject),
				null // key store
			);
		} catch (Exception e) {
			throw new ParseException(e.getMessage(), 0);
		}
	}
	
	
	/**
	 * Loads an octet sequence JWK from the specified JCA key store.
	 *
	 * @param keyStore The key store. Must not be {@code null}.
	 * @param alias    The alias. Must not be {@code null}.
	 * @param pin      The pin to unlock the private key if any, empty or
	 *                 {@code null} if not required.
	 *
	 * @return The octet sequence JWK, {@code null} if no key with the
	 *         specified alias was found.
	 *
	 * @throws KeyStoreException On a key store exception.
	 * @throws JOSEException     If octet sequence key loading failed.
	 */
	public static OctetSequenceKey load(final KeyStore keyStore, final String alias, final char[] pin)
		throws KeyStoreException, JOSEException {
		
		Key key;
		try {
			key = keyStore.getKey(alias, pin);
		} catch (UnrecoverableKeyException | NoSuchAlgorithmException e) {
			throw new JOSEException("Couldn't retrieve secret key (bad pin?): " + e.getMessage(), e);
		}
		
		if (! (key instanceof SecretKey)) {
			return null;
		}
		
		return new OctetSequenceKey.Builder((SecretKey)key)
			.keyID(alias)
			.keyStore(keyStore)
			.build();
	}

	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof OctetSequenceKey)) return false;
		if (!super.equals(o)) return false;
		OctetSequenceKey that = (OctetSequenceKey) o;
		return Objects.equals(k, that.k);
	}

	
	@Override
	public int hashCode() {
		return Objects.hash(super.hashCode(), k);
	}
}
