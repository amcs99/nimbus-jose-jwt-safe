/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2019, Connect2id Ltd.
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


import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import net.jcip.annotations.Immutable;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.X509CertUtils;


/**
 * JSON Web Key (JWK) matcher. May be used to ensure a JWK matches a set of
 * application-specific criteria.
 *
 * <p>Supported key matching criteria:
 *
 * <ul>
 *     <li>Any, unspecified, one or more key types (typ).
 *     <li>Any, unspecified, one or more key uses (use).
 *     <li>Any, unspecified, one or more key operations (key_ops).
 *     <li>Any, unspecified, one or more key algorithms (alg).
 *     <li>Any, unspecified, one or more key identifiers (kid).
 *     <li>Private key only.
 *     <li>Public key only.
 *     <li>Non-revoked key only.
 *     <li>Revoked key only.
 *     <li>Minimum, maximum or exact key sizes.
 *     <li>Any, unspecified, one or more curves for EC and OKP keys (crv).
 *     <li>X.509 certificate SHA-256 thumbprint.
 *     <li>With X.509 certificate only.
 * </ul>
 *
 * <p>Matching by JWK thumbprint (RFC 7638), X.509 certificate URL and X.509
 * certificate chain is not supported.
 *
 * @author Vladimir Dzhuvinov
 * @author Josh Cummings
 * @author Ben Arena
 * @version 2024-11-01
 */
@Immutable
public class JWKMatcher {


	/**
	 * The key types to match.
	 */
	private final Set<KeyType> types;


	/**
	 * The public key uses to match.
	 */
	private final Set<KeyUse> uses;


	/**
	 * The key operations to match.
	 */
	private final Set<KeyOperation> ops;


	/**
	 * The algorithms to match.
	 */
	private final Set<Algorithm> algs;


	/**
	 * The key IDs to match.
	 */
	private final Set<String> ids;
	
	
	/**
	 * {@code true} to match a key with a specified use only.
	 */
	private final boolean withUseOnly;
	
	
	/**
	 * {@code true} to match a key with a specified ID only.
	 */
	private final boolean withIDOnly;


	/**
	 * {@code true} to match a private key only.
	 */
	private final boolean privateOnly;


	/**
	 * {@code true} to match a public key only.
	 */
	private final boolean publicOnly;


	/**
	 * {@code true} to match a non-revoked key only.
	 */
	private final boolean nonRevokedOnly;


	/**
	 * {@code true} to match a revoked key only.
	 */
	private final boolean revokedOnly;


	/**
	 * The minimum key size in bits, zero implies no minimum size.
	 */
	private final int minSizeBits;


	/**
	 * The maximum key size in bits, zero implies no maximum size.
	 */
	private final int maxSizeBits;
	
	
	/**
	 * The key sizes in bits.
	 */
	private final Set<Integer> sizesBits;
	
	
	/**
	 * The curves to match (for EC and OKP keys).
	 */
	private final Set<Curve> curves;

	
	/**
	 * The X.509 certificate SHA-256 thumbprints to match.
	 */
	private final Set<Base64URL> x5tS256s;
	
	
	/**
	 * {@code true} to match a key with a specified X.509 certificate chain
	 * only.
	 */
	private final boolean withX5COnly;

	
	/**
	 * Builder for constructing JWK matchers.
	 *
	 * <p>Example usage:
	 *
	 * <pre>
	 * JWKMatcher matcher = new JWKMatcher().keyID("123").build();
	 * </pre>
	 */
	public static class Builder {

		
		/**
		 * The key types to match.
		 */
		private Set<KeyType> types;


		/**
		 * The public key uses to match.
		 */
		private Set<KeyUse> uses;


		/**
		 * The key operations to match.
		 */
		private Set<KeyOperation> ops;


		/**
		 * The algorithms to match.
		 */
		private Set<Algorithm> algs;


		/**
		 * The key IDs to match.
		 */
		private Set<String> ids;
		
		
		/**
		 * {@code true} to match a key with specified use only.
		 */
		private boolean withUseOnly = false;
		
		
		/**
		 * {@code true} to match a key with a specified ID only.
		 */
		private boolean withIDOnly = false;


		/**
		 * {@code true} to match a private key only.
		 */
		private boolean privateOnly = false;


		/**
		 * {@code true} to match a public key only.
		 */
		private boolean publicOnly = false;


		/**
		 * {@code true} to match a non-revoked key only.
		 */
		private boolean nonRevokedOnly = false;


		/**
		 * {@code true} to match a revoked key only.
		 */
		private boolean revokedOnly = false;


		/**
		 * The minimum key size in bits, zero implies no minimum size
		 * limit.
		 */
		private int minSizeBits = 0;


		/**
		 * The maximum key size in bits, zero implies no maximum size
		 * limit.
		 */
		private int maxSizeBits = 0;
		
		
		/**
		 * The key sizes in bits.
		 */
		private Set<Integer> sizesBits;
		
		
		/**
		 * The curves to match (for EC and OKP keys).
		 */
		private Set<Curve> curves;

		
		/**
		 * The X.509 certificate SHA-256 thumbprints to match.
		 */
		private Set<Base64URL> x5tS256s;
		
		
		/**
		 * {@code true} to match a key with a specified X.509
		 * certificate chain only.
		 */
		private boolean withX5COnly = false;


		/**
		 * Creates a new builder for constructing JWK matchers.
		 */
		public Builder() {
		}


		/**
		 * Creates a new builder for constructing JWK matchers using
		 * the specified matcher.
		 *
		 * @param jwkMatcher The JWK matcher to use. Must not be
		 *                   {@code null}.
		 */
		public Builder(final JWKMatcher jwkMatcher) {
			types = jwkMatcher.getKeyTypes();
			uses = jwkMatcher.getKeyUses();
			ops = jwkMatcher.getKeyOperations();
			algs = jwkMatcher.getAlgorithms();
			ids = jwkMatcher.getKeyIDs();
			withUseOnly = jwkMatcher.isWithKeyUseOnly();
			withIDOnly = jwkMatcher.isWithKeyIDOnly();
			privateOnly = jwkMatcher.isPrivateOnly();
			publicOnly = jwkMatcher.isPublicOnly();
			nonRevokedOnly = jwkMatcher.isNonRevokedOnly();
			revokedOnly = jwkMatcher.isNonRevokedOnly();
			minSizeBits = jwkMatcher.getMinKeySize();
			maxSizeBits = jwkMatcher.getMaxKeySize();
			sizesBits = jwkMatcher.getKeySizes();
			curves = jwkMatcher.getCurves();
			x5tS256s = jwkMatcher.getX509CertSHA256Thumbprints();
			withX5COnly = jwkMatcher.isWithX509CertChainOnly();
		}


		/**
		 * Sets a single key type to match.
		 *
		 * @param kty The key type, {@code null} if not specified.
		 *            
		 * @return This builder.            
		 */
		public Builder keyType(final KeyType kty) {

			if (kty == null) {
				types = null;
			} else {
				types = new HashSet<>(Collections.singletonList(kty));
			}
			
			return this;
		}


		/**
		 * Sets multiple key types to match.
		 *
		 * @param types The key types.
		 *
		 * @return This builder.
		 */
		public Builder keyTypes(final KeyType ... types) {

			keyTypes(new LinkedHashSet<>(Arrays.asList(types)));
			return this;
		}


		/**
		 * Sets multiple key types to match.
		 *
		 * @param types The key types, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder keyTypes(final Set<KeyType> types) {

			this.types = types;
			return this;
		}


		/**
		 * Sets a single public key use to match.
		 *
		 * @param use The public key use, {@code null} if not 
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder keyUse(final KeyUse use) {

			if (use == null) {
				uses = null;
			} else {
				uses = new HashSet<>(Collections.singletonList(use));
			}
			return this;
		}


		/**
		 * Sets multiple public key uses to match.
		 *
		 * @param uses The public key uses.
		 *
		 * @return This builder.
		 */
		public Builder keyUses(final KeyUse... uses) {

			keyUses(new LinkedHashSet<>(Arrays.asList(uses)));
			return this;
		}


		/**
		 * Sets multiple public key uses to match.
		 *
		 * @param uses The public key uses, {@code null} if not
		 *             specified.
		 *
		 * @return This builder.
		 */
		public Builder keyUses(final Set<KeyUse> uses) {

			this.uses = uses;
			return this;
		}


		/**
		 * Sets a single key operation to match.
		 *
		 * @param op The key operation, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder keyOperation(final KeyOperation op) {

			if (op == null) {
				ops = null;
			} else {
				ops = new HashSet<>(Collections.singletonList(op));
			}
			return this;
		}


		/**
		 * Sets multiple key operations to match.
		 *
		 * @param ops The key operations.
		 *
		 * @return This builder.
		 */
		public Builder keyOperations(final KeyOperation... ops) {

			keyOperations(new LinkedHashSet<>(Arrays.asList(ops)));
			return this;
		}


		/**
		 * Sets multiple key operations to match.
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
		 * Sets a single JOSE algorithm to match.
		 *
		 * @param alg The JOSE algorithm, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder algorithm(final Algorithm alg) {

			if (alg == null) {
				algs = null;
			} else {
				algs = new HashSet<>(Collections.singletonList(alg));
			}
			return this;
		}


		/**
		 * Sets multiple JOSE algorithms to match.
		 *
		 * @param algs The JOSE algorithms.
		 *
		 * @return This builder.
		 */
		public Builder algorithms(final Algorithm ... algs) {

			algorithms(new LinkedHashSet<>(Arrays.asList(algs)));
			return this;
		}


		/**
		 * Sets multiple JOSE algorithms to match.
		 *
		 * @param algs The JOSE algorithms, {@code null} if not
		 *             specified.
		 *
		 * @return This builder.
		 */
		public Builder algorithms(final Set<Algorithm> algs) {

			this.algs = algs;
			return this;
		}


		/**
		 * Sets a single key ID to match.
		 *
		 * @param id The key ID, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder keyID(final String id) {

			if (id == null) {
				ids = null;
			} else {
				ids = new HashSet<>(Collections.singletonList(id));
			}
			return this;
		}


		/**
		 * Sets multiple key IDs to match.
		 *
		 * @param ids The key IDs.
		 *
		 * @return This builder.
		 */
		public Builder keyIDs(final String ... ids) {

			keyIDs(new LinkedHashSet<>(Arrays.asList(ids)));
			return this;
		}


		/**
		 * Sets multiple key IDs to match.
		 *
		 * @param ids The key IDs, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder keyIDs(final Set<String> ids) {

			this.ids = ids;
			return this;
		}
		
		
		/**
		 * Sets the key use presence matching.
		 *
		 * @param hasUse {@code true} to match a key with a specified
		 *               use only.
		 *
		 * @return This builder.
		 */
		@Deprecated
		public Builder hasKeyUse(final boolean hasUse) {
			
			return withKeyUseOnly(hasUse);
		}


		/**
		 * Sets the key use presence matching.
		 *
		 * @param withUseOnly {@code true} to match a key with a
		 *                    specified use only.
		 *
		 * @return This builder.
		 */
		public Builder withKeyUseOnly(final boolean withUseOnly) {

			this.withUseOnly = withUseOnly;
			return this;
		}
		
		
		/**
		 * Sets the key ID presence matching.
		 *
		 * @param hasID {@code true} to match a key a specified ID
		 *              only.
		 *
		 * @return This builder.
		 */
		@Deprecated
		public Builder hasKeyID(final boolean hasID) {
			
			return withKeyIDOnly(hasID);
		}


		/**
		 * Sets the key ID presence matching.
		 *
		 * @param withIDOnly {@code true} to match a key a specified ID
		 *                   only.
		 *
		 * @return This builder.
		 */
		public Builder withKeyIDOnly(final boolean withIDOnly) {

			this.withIDOnly = withIDOnly;
			return this;
		}


		/**
		 * Sets the private key matching.
		 *
		 * @param privateOnly {@code true} to match a private key only.
		 *
		 * @return This builder.
		 */
		public Builder privateOnly(final boolean privateOnly) {

			this.privateOnly = privateOnly;
			return this;
		}


		/**
		 * Sets the public key matching.
		 *
		 * @param publicOnly {@code true} to match a public key only.
		 *
		 * @return This builder.
		 */
		public Builder publicOnly(final boolean publicOnly) {

			this.publicOnly = publicOnly;
			return this;
		}


		/**
		 * Sets the non-revoked key matching.
		 *
		 * @param nonRevokedOnly {@code true} to match a non-revoked
		 *                       key only.
		 *
		 * @return This builder.
		 */
		public Builder nonRevokedOnly(final boolean nonRevokedOnly) {

			this.nonRevokedOnly = nonRevokedOnly;
			return this;
		}


		/**
		 * Sets the revoked key matching.
		 *
		 * @param revokedOnly {@code true} to match a revoked key only.
		 *
		 * @return This builder.
		 */
		public Builder revokedOnly(final boolean revokedOnly) {

			this.revokedOnly = revokedOnly;
			return this;
		}


		/**
		 * Sets the minimal key size.
		 *
		 * @param minSizeBits The minimum key size in bits, zero
		 *                    implies no minimum key size limit.
		 *
		 * @return This builder.
		 */
		public Builder minKeySize(final int minSizeBits) {

			this.minSizeBits = minSizeBits;
			return this;
		}


		/**
		 * Sets the maximum key size.
		 *
		 * @param maxSizeBits The maximum key size in bits, zero
		 *                    implies no maximum key size limit.
		 *
		 * @return This builder.
		 */
		public Builder maxKeySize(final int maxSizeBits) {

			this.maxSizeBits = maxSizeBits;
			return this;
		}
		
		
		/**
		 * Sets the key size.
		 *
		 * @param keySizeBits The key size in bits, zero if not
		 *                    specified.
		 *
		 * @return This builder.
		 */
		public Builder keySize(final int keySizeBits) {
			if (keySizeBits <= 0) {
				sizesBits = null;
			} else {
				sizesBits = Collections.singleton(keySizeBits);
			}
			return this;
		}
		
		
		/**
		 * Sets the key sizes.
		 *
		 * @param keySizesBits The key sizes in bits.
		 *
		 * @return This builder.
		 */
		public Builder keySizes(final int... keySizesBits) {
			Set<Integer> sizesSet = new LinkedHashSet<>();
			for (int keySize: keySizesBits) {
				sizesSet.add(keySize);
			}
			keySizes(sizesSet);
			return this;
		}
		
		
		/**
		 * Sets the key sizes.
		 *
		 * @param keySizesBits The key sizes in bits.
		 *
		 * @return This builder.
		 */
		public Builder keySizes(final Set<Integer> keySizesBits) {
			
			this.sizesBits = keySizesBits;
			return this;
		}
		
		
		/**
		 * Sets a single curve to match (for EC and OKP keys).
		 *
		 * @param curve The curve, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder curve(final Curve curve) {
			
			if (curve == null) {
				curves = null;
			} else {
				curves = Collections.singleton(curve);
			}
			return this;
		}
		
		
		/**
		 * Sets multiple curves to match (for EC and OKP keys).
		 *
		 * @param curves The curves.
		 *
		 * @return This builder.
		 */
		public Builder curves(final Curve... curves) {
			
			curves(new LinkedHashSet<>(Arrays.asList(curves)));
			return this;
		}
		
		
		/**
		 * Sets multiple curves to match (for EC and OKP keys).
		 *
		 * @param curves The curves, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder curves(final Set<Curve> curves) {
			
			this.curves = curves;
			return this;
		}

		
		/**
		 * Sets a single X.509 certificate SHA-256 thumbprint to match.
		 *
		 * @param x5tS256 The thumbprint, {@code null} if not
		 *                specified.
		 *
		 * @return This builder.
		 */
		public Builder x509CertSHA256Thumbprint(final Base64URL x5tS256) {

			if (x5tS256 == null) {
				x5tS256s = null;
			} else {
				x5tS256s = Collections.singleton(x5tS256);
			}
			return this;
		}

		
		/**
		 * Sets multiple X.509 certificate SHA-256 thumbprints to
		 * match.
		 *
		 * @param x5tS256s The thumbprints.
		 *
		 * @return This builder.
		 */
		public Builder x509CertSHA256Thumbprints(final Base64URL... x5tS256s) {
			return x509CertSHA256Thumbprints(new LinkedHashSet<>(Arrays.asList(x5tS256s)));
		}

		
		/**
		 * Sets multiple X.509 certificate SHA-256 thumbprints to
		 * match.
		 *
		 * @param x5tS256s The thumbprints, {@code null} if not
		 *                 specified.
		 *
		 * @return This builder.
		 */
		public Builder x509CertSHA256Thumbprints(final Set<Base64URL> x5tS256s) {
			this.x5tS256s = x5tS256s;
			return this;
		}
		
		
		/**
		 * Sets the X.509 certificate chain presence matching.
		 *
		 * @param hasX5C {@code true} to match a key with a specified
		 *               X.509 certificate chain only.
		 *
		 * @return This builder.
		 */
		@Deprecated
		public Builder hasX509CertChain(final boolean hasX5C) {

			return withX509CertChainOnly(hasX5C);
		}


		/**
		 * Sets the X.509 certificate chain presence matching.
		 *
		 * @param withX5CONly {@code true} to match a key with a
		 *                    specified X.509 certificate chain only.
		 *
		 * @return This builder.
		 */
		public Builder withX509CertChainOnly(final boolean withX5CONly) {

			this.withX5COnly = withX5CONly;
			return this;
		}

		
		/**
		 * Builds a new JWK matcher.
		 *
		 * @return The JWK matcher.
		 */
		public JWKMatcher build() {

			return new JWKMatcher(
				types, uses, ops, algs, ids,
				withUseOnly, withIDOnly,
				privateOnly, publicOnly,
				nonRevokedOnly, revokedOnly,
				minSizeBits, maxSizeBits, sizesBits,
				curves,
				x5tS256s, withX5COnly);
		}
	}


	/**
	 * Creates a new JSON Web Key (JWK) matcher.
	 *
	 * @param types       The key types to match, {@code null} if not
	 *                    specified.
	 * @param uses        The public key uses to match, {@code null} if not
	 *                    specified.
	 * @param ops         The key operations to match, {@code null} if not
	 *                    specified.
	 * @param algs        The JOSE algorithms to match, {@code null} if not
	 *                    specified.
	 * @param ids         The key IDs to match, {@code null} if not
	 *                    specified.
	 * @param privateOnly {@code true} to match a private key.
	 * @param publicOnly  {@code true} to match a public only key.
	 */
	@Deprecated
	public JWKMatcher(final Set<KeyType> types,
			  final Set<KeyUse> uses,
			  final Set<KeyOperation> ops,
			  final Set<Algorithm> algs,
			  final Set<String> ids,
			  final boolean privateOnly,
			  final boolean publicOnly) {

		this(types, uses, ops, algs, ids, privateOnly, publicOnly, 0, 0);
	}


	/**
	 * Creates a new JSON Web Key (JWK) matcher.
	 *
	 * @param types       The key types to match, {@code null} if not
	 *                    specified.
	 * @param uses        The public key uses to match, {@code null} if not
	 *                    specified.
	 * @param ops         The key operations to match, {@code null} if not
	 *                    specified.
	 * @param algs        The JOSE algorithms to match, {@code null} if not
	 *                    specified.
	 * @param ids         The key IDs to match, {@code null} if not
	 *                    specified.
	 * @param privateOnly {@code true} to match a private key.
	 * @param publicOnly  {@code true} to match a public only key.
	 * @param minSizeBits The minimum key size in bits, zero implies no
	 *                    minimum size limit.
	 * @param maxSizeBits The maximum key size in bits, zero implies no
	 *                    maximum size limit.
	 */
	@Deprecated
	public JWKMatcher(final Set<KeyType> types,
			  final Set<KeyUse> uses,
			  final Set<KeyOperation> ops,
			  final Set<Algorithm> algs,
			  final Set<String> ids,
			  final boolean privateOnly,
			  final boolean publicOnly,
			  final int minSizeBits,
			  final int maxSizeBits) {
		
		this(types, uses, ops, algs, ids, privateOnly, publicOnly, minSizeBits, maxSizeBits, null);
	}


	/**
	 * Creates a new JSON Web Key (JWK) matcher.
	 *
	 * @param types       The key types to match, {@code null} if not
	 *                    specified.
	 * @param uses        The public key uses to match, {@code null} if not
	 *                    specified.
	 * @param ops         The key operations to match, {@code null} if not
	 *                    specified.
	 * @param algs        The JOSE algorithms to match, {@code null} if not
	 *                    specified.
	 * @param ids         The key IDs to match, {@code null} if not
	 *                    specified.
	 * @param privateOnly {@code true} to match a private key.
	 * @param publicOnly  {@code true} to match a public only key.
	 * @param minSizeBits The minimum key size in bits, zero implies no
	 *                    minimum size limit.
	 * @param maxSizeBits The maximum key size in bits, zero implies no
	 *                    maximum size limit.
	 * @param curves      The curves to match (for EC keys), {@code null}
	 *                    if not specified.
	 */
	@Deprecated
	public JWKMatcher(final Set<KeyType> types,
			  final Set<KeyUse> uses,
			  final Set<KeyOperation> ops,
			  final Set<Algorithm> algs,
			  final Set<String> ids,
			  final boolean privateOnly,
			  final boolean publicOnly,
			  final int minSizeBits,
			  final int maxSizeBits,
			  final Set<Curve> curves) {
		
		this(types, uses, ops, algs, ids, privateOnly, publicOnly, minSizeBits, maxSizeBits, null, curves);
	}


	/**
	 * Creates a new JSON Web Key (JWK) matcher.
	 *
	 * @param types       The key types to match, {@code null} if not
	 *                    specified.
	 * @param uses        The public key uses to match, {@code null} if not
	 *                    specified.
	 * @param ops         The key operations to match, {@code null} if not
	 *                    specified.
	 * @param algs        The JOSE algorithms to match, {@code null} if not
	 *                    specified.
	 * @param ids         The key IDs to match, {@code null} if not
	 *                    specified.
	 * @param privateOnly {@code true} to match a private key.
	 * @param publicOnly  {@code true} to match a public only key.
	 * @param minSizeBits The minimum key size in bits, zero implies no
	 *                    minimum size limit.
	 * @param maxSizeBits The maximum key size in bits, zero implies no
	 *                    maximum size limit.
	 * @param sizesBits   The key sizes in bits, {@code null} if not
	 *                    specified.
	 * @param curves      The curves to match (for EC and OKP keys),
	 *                    {@code null} if not specified.
	 */
	@Deprecated
	public JWKMatcher(final Set<KeyType> types,
			  final Set<KeyUse> uses,
			  final Set<KeyOperation> ops,
			  final Set<Algorithm> algs,
			  final Set<String> ids,
			  final boolean privateOnly,
			  final boolean publicOnly,
			  final int minSizeBits,
			  final int maxSizeBits,
			  final Set<Integer> sizesBits,
			  final Set<Curve> curves) {
		
		this(types, uses, ops, algs, ids, false, false, privateOnly, publicOnly, minSizeBits, maxSizeBits, sizesBits, curves);
	}


	/**
	 * Creates a new JSON Web Key (JWK) matcher.
	 *
	 * @param types       The key types to match, {@code null} if not
	 *                    specified.
	 * @param uses        The public key uses to match, {@code null} if not
	 *                    specified.
	 * @param ops         The key operations to match, {@code null} if not
	 *                    specified.
	 * @param algs        The JOSE algorithms to match, {@code null} if not
	 *                    specified.
	 * @param ids         The key IDs to match, {@code null} if not
	 *                    specified.
	 * @param withUseOnly      {@code true} to match a key with a set use.
	 * @param withIDOnly       {@code true} to match a key with a set ID.
	 * @param privateOnly {@code true} to match a private key.
	 * @param publicOnly  {@code true} to match a public only key.
	 * @param minSizeBits The minimum key size in bits, zero implies no
	 *                    minimum size limit.
	 * @param maxSizeBits The maximum key size in bits, zero implies no
	 *                    maximum size limit.
	 * @param sizesBits   The key sizes in bits, {@code null} if not
	 *                    specified.
	 * @param curves      The curves to match (for EC and OKP keys),
	 *                    {@code null} if not specified.
	 */
	@Deprecated
	public JWKMatcher(final Set<KeyType> types,
			  final Set<KeyUse> uses,
			  final Set<KeyOperation> ops,
			  final Set<Algorithm> algs,
			  final Set<String> ids,
			  final boolean withUseOnly,
			  final boolean withIDOnly,
			  final boolean privateOnly,
			  final boolean publicOnly,
			  final int minSizeBits,
			  final int maxSizeBits,
			  final Set<Integer> sizesBits,
			  final Set<Curve> curves) {

		this(types, uses, ops, algs, ids, withUseOnly, withIDOnly, privateOnly, publicOnly, minSizeBits, maxSizeBits, sizesBits, curves, null);
	}

	
	/**
	 * Creates a new JSON Web Key (JWK) matcher.
	 *
	 * @param types       The key types to match, {@code null} if not
	 *                    specified.
	 * @param uses        The public key uses to match, {@code null} if not
	 *                    specified.
	 * @param ops         The key operations to match, {@code null} if not
	 *                    specified.
	 * @param algs        The JOSE algorithms to match, {@code null} if not
	 *                    specified.
	 * @param ids         The key IDs to match, {@code null} if not
	 *                    specified.
	 * @param withUseOnly      {@code true} to match a key with a set use.
	 * @param withIDOnly       {@code true} to match a key with a set ID.
	 * @param privateOnly {@code true} to match a private key.
	 * @param publicOnly  {@code true} to match a public only key.
	 * @param minSizeBits The minimum key size in bits, zero implies no
	 *                    minimum size limit.
	 * @param maxSizeBits The maximum key size in bits, zero implies no
	 *                    maximum size limit.
	 * @param sizesBits   The key sizes in bits, {@code null} if not
	 *                    specified.
	 * @param curves      The curves to match (for EC and OKP keys),
	 *                    {@code null} if not specified.
	 * @param x5tS256s    The X.509 certificate thumbprints to match,
	 *                    {@code null} if not specified.
	 */
	@Deprecated
	public JWKMatcher(final Set<KeyType> types,
			  final Set<KeyUse> uses,
			  final Set<KeyOperation> ops,
			  final Set<Algorithm> algs,
			  final Set<String> ids,
			  final boolean withUseOnly,
			  final boolean withIDOnly,
			  final boolean privateOnly,
			  final boolean publicOnly,
			  final int minSizeBits,
			  final int maxSizeBits,
			  final Set<Integer> sizesBits,
			  final Set<Curve> curves,
			  final Set<Base64URL> x5tS256s) {

		this(types, uses, ops, algs, ids, withUseOnly, withIDOnly, privateOnly, publicOnly, minSizeBits, maxSizeBits, sizesBits, curves, x5tS256s, false);
	}

	
	/**
	 * Creates a new JSON Web Key (JWK) matcher.
	 *
	 * @param types       The key types to match, {@code null} if not
	 *                    specified.
	 * @param uses        The public key uses to match, {@code null} if not
	 *                    specified.
	 * @param ops         The key operations to match, {@code null} if not
	 *                    specified.
	 * @param algs        The JOSE algorithms to match, {@code null} if not
	 *                    specified.
	 * @param ids         The key IDs to match, {@code null} if not
	 *                    specified.
	 * @param withUseOnly      {@code true} to match a key with a set use.
	 * @param withIDOnly       {@code true} to match a key with a set ID.
	 * @param privateOnly {@code true} to match a private key.
	 * @param publicOnly  {@code true} to match a public only key.
	 * @param minSizeBits The minimum key size in bits, zero implies no
	 *                    minimum size limit.
	 * @param maxSizeBits The maximum key size in bits, zero implies no
	 *                    maximum size limit.
	 * @param sizesBits   The key sizes in bits, {@code null} if not
	 *                    specified.
	 * @param curves      The curves to match (for EC and OKP keys),
	 *                    {@code null} if not specified.
	 * @param x5tS256s    The X.509 certificate thumbprints to match,
	 *                    {@code null} if not specified.
	 * @param withX5COnly      {@code true} to match a key with a set X.509
	 *                    certificate chain.
	 */
	@Deprecated
	public JWKMatcher(final Set<KeyType> types,
					  final Set<KeyUse> uses,
					  final Set<KeyOperation> ops,
					  final Set<Algorithm> algs,
					  final Set<String> ids,
					  final boolean withUseOnly,
					  final boolean withIDOnly,
					  final boolean privateOnly,
					  final boolean publicOnly,
					  final int minSizeBits,
					  final int maxSizeBits,
					  final Set<Integer> sizesBits,
					  final Set<Curve> curves,
					  final Set<Base64URL> x5tS256s,
			  		  final boolean withX5COnly) {

		this(types, uses, ops, algs, ids, withUseOnly, withIDOnly, privateOnly, publicOnly, false, false, minSizeBits, maxSizeBits, sizesBits, curves, x5tS256s, withX5COnly);
	}


	/**
	 * Creates a new JSON Web Key (JWK) matcher.
	 *
	 * @param types          The key types to match, {@code null} if not
	 *                       specified.
	 * @param uses           The public key uses to match, {@code null} if
	 *                       not specified.
	 * @param ops            The key operations to match, {@code null} if
	 *                       not specified.
	 * @param algs           The JOSE algorithms to match, {@code null} if
	 *                       not specified.
	 * @param ids            The key IDs to match, {@code null} if not
	 *                       specified.
	 * @param withUseOnly         {@code true} to match a key with a set use.
	 * @param withIDOnly          {@code true} to match a key with a set ID.
	 * @param privateOnly    {@code true} to match a private key only.
	 * @param publicOnly     {@code true} to match a public key only.
	 * @param nonRevokedOnly {@code true} to match a non-revoked key only.
	 * @param revokedOnly    {@code true} to match a revoked key only.
	 * @param minSizeBits    The minimum key size in bits, zero implies no
	 *                       minimum size.
	 * @param maxSizeBits    The maximum key size in bits, zero implies no
	 *                       maximum size.
	 * @param sizesBits      The key sizes in bits, {@code null} if not
	 *                       specified.
	 * @param curves         The curves to match (for EC and OKP keys),
	 *                       {@code null} if not specified.
	 * @param x5tS256s       The X.509 certificate thumbprints to match,
	 *                       {@code null} if not specified.
	 * @param withX5COnly         {@code true} to match a key with a set X.509
	 *                       certificate chain.
	 */
	public JWKMatcher(final Set<KeyType> types,
			  final Set<KeyUse> uses,
			  final Set<KeyOperation> ops,
			  final Set<Algorithm> algs,
			  final Set<String> ids,
			  final boolean withUseOnly,
			  final boolean withIDOnly,
			  final boolean privateOnly,
			  final boolean publicOnly,
			  final boolean nonRevokedOnly,
			  final boolean revokedOnly,
			  final int minSizeBits,
			  final int maxSizeBits,
			  final Set<Integer> sizesBits,
			  final Set<Curve> curves,
			  final Set<Base64URL> x5tS256s,
			  final boolean withX5COnly) {

		this.types = types;
		this.uses = uses;
		this.ops = ops;
		this.algs = algs;
		this.ids = ids;
		this.withUseOnly = withUseOnly;
		this.withIDOnly = withIDOnly;
		this.privateOnly = privateOnly;
		this.publicOnly = publicOnly;
		this.nonRevokedOnly = nonRevokedOnly;
		this.revokedOnly = revokedOnly;
		this.minSizeBits = minSizeBits;
		this.maxSizeBits = maxSizeBits;
		this.sizesBits = sizesBits;
		this.curves = curves;
		this.x5tS256s = x5tS256s;
		this.withX5COnly = withX5COnly;
	}

	
	/**
	 * Returns a {@link JWKMatcher} based on the given {@link JWEHeader}.
	 *
	 * <p>The {@link JWKMatcher} is configured as follows:
	 *
	 * <ul>
	 *     <li>The key type to match is determined by the JWE algorithm
	 *         (alg).
	 *     <li>The key ID to match is set by the JWE header key ID (kid)
	 *         parameter (if set).
	 *     <li>The key uses to match are set to encryption or not
	 *         specified.
	 *     <li>The key algorithm to match is set to the JWE algorithm (alg)
	 *         or not specified.
	 * </ul>
	 *
	 * <p>Other JWE header parameters are not taken into account.
	 *
	 * @param jweHeader The header to use.
	 *
	 * @return A {@code JWKMatcher} based on the given header.
	 */
	public static JWKMatcher forJWEHeader(final JWEHeader jweHeader) {

		return new JWKMatcher.Builder()
			.keyType(KeyType.forAlgorithm(jweHeader.getAlgorithm()))
			.keyID(jweHeader.getKeyID())
			.keyUses(KeyUse.ENCRYPTION, null)
			.algorithms(jweHeader.getAlgorithm(), null)
			.build();
	}

	
	/**
	 * Returns a {@link JWKMatcher} based on the given {@link JWSHeader}.
	 *
	 * <p>The {@link JWKMatcher} is configured as follows:
	 *
	 * <ul>
	 *     <li>The key type to match is determined by the JWS algorithm
	 *         (alg).
	 *     <li>The key ID to match is set by the JWS header key ID (kid)
	 *         parameter (if set).
	 *     <li>The key uses to match are set to signature or not specified.
	 *     <li>The key algorithm to match is set to the JWS algorithm (alg)
	 *         or not specified.
	 *     <li>The X.509 certificate SHA-256 thumbprint to match is set to
	 *         the x5t#S256 parameter (if set).
	 * </ul>
	 *
	 * <p>Other JWS header parameters are not taken into account.
	 *
	 * @param jwsHeader The header to use.
	 *
	 * @return A {@code JWKMatcher} based on the given header, {@code null}
	 *         if the JWS algorithm is not supported.
	 */
	public static JWKMatcher forJWSHeader(final JWSHeader jwsHeader) {

		JWSAlgorithm algorithm = jwsHeader.getAlgorithm();
		if (JWSAlgorithm.Family.RSA.contains(algorithm) || JWSAlgorithm.Family.EC.contains(algorithm)) {
			// RSA or EC key matcher
			return new JWKMatcher.Builder()
				.keyType(KeyType.forAlgorithm(algorithm))
				.keyID(jwsHeader.getKeyID())
				.keyUses(KeyUse.SIGNATURE, null)
				.algorithms(algorithm, null)
				.x509CertSHA256Thumbprint(jwsHeader.getX509CertSHA256Thumbprint())
				.build();
		} else if (JWSAlgorithm.Family.HMAC_SHA.contains(algorithm)) {
			// HMAC secret matcher
			return new JWKMatcher.Builder()
				.keyType(KeyType.forAlgorithm(algorithm))
				.keyID(jwsHeader.getKeyID())
				.privateOnly(true)
				.algorithms(algorithm, null)
				.build();
		} else if (JWSAlgorithm.Family.ED.contains(algorithm)) {
			return new JWKMatcher.Builder()
				.keyType(KeyType.forAlgorithm(algorithm))
				.keyID(jwsHeader.getKeyID())
				.keyUses(KeyUse.SIGNATURE, null)
				.algorithms(algorithm, null)
				.curves(Curve.forJWSAlgorithm(algorithm))
				.build();
		} else {
			return null; // Unsupported algorithm
		}
	}
	

	/**
	 * Returns the key types to match.
	 *
	 * @return The key types, {@code null} if not specified.
	 */
	public Set<KeyType> getKeyTypes() {

		return types;
	}


	/**
	 * Returns the public key uses to match.
	 *
	 * @return The public key uses, {@code null} if not specified.
	 */
	public Set<KeyUse> getKeyUses() {

		return uses;
	}


	/**
	 * Returns the key operations to match.
	 *
	 * @return The key operations, {@code null} if not specified.
	 */
	public Set<KeyOperation> getKeyOperations() {

		return ops;
	}


	/**
	 * Returns the JOSE algorithms to match.
	 *
	 * @return The JOSE algorithms, {@code null} if not specified.
	 */
	public Set<Algorithm> getAlgorithms() {

		return algs;
	}


	/**
	 * Returns the key IDs to match.
	 *
	 * @return The key IDs, {@code null} if not specified.
	 */
	public Set<String> getKeyIDs() {

		return ids;
	}
	
	
	/**
	 * Returns {@code true} if keys with a specified use are matched.
	 *
	 * @return {@code true} if keys with a specified use are matched, else
	 *         {@code false}.
	 */
	@Deprecated
	public boolean hasKeyUse() {
		
		return isWithKeyUseOnly();
	}


	/**
	 * Returns {@code true} if keys with a specified use are matched.
	 *
	 * @return {@code true} if keys with a specified use are matched, else
	 *         {@code false}.
	 */
	public boolean isWithKeyUseOnly() {

		return withUseOnly;
	}
	
	
	/**
	 * Returns {@code true} if keys with a specified ID are matched.
	 *
	 * @return {@code true} if keys with a specified ID are matched, else
	 *         {@code false}.
	 */
	@Deprecated
	public boolean hasKeyID() {
		
		return isWithKeyIDOnly();
	}


	/**
	 * Returns {@code true} if keys with a specified ID are matched.
	 *
	 * @return {@code true} if keys with a specified ID are matched, else
	 *         {@code false}.
	 */
	public boolean isWithKeyIDOnly() {

		return withIDOnly;
	}


	/**
	 * Returns {@code true} if only private keys are matched.
	 *
	 * @return {@code true} if only private keys are matched, else 
	 *         {@code false}.
	 */
	public boolean isPrivateOnly() {

		return privateOnly;
	}


	/**
	 * Returns {@code true} if only public keys are matched.
	 *
	 * @return {@code true} if only public keys are matched, else
	 *         {@code false}.
	 */
	public boolean isPublicOnly() {

		return publicOnly;
	}


	/**
	 * Returns {@code true} if only non-revoked keys are matched.
	 * 
	 * @return {@code true} if only non-revoked keys are matched, else
	 *         {@code false}.
	 */
	public boolean isNonRevokedOnly() {
		
		return nonRevokedOnly;
	}


	/**
	 * Returns {@code true} if only revoked keys are matched.
	 *
	 * @return {@code true} if only revoked keys are matched, else
	 *         {@code false}.
	 */
	public boolean isRevokedOnly() {

		return revokedOnly;
	}


	/**
	 * Returns the minimum key size. Use {@link #getMinKeySize()} instead.
	 *
	 * @return The minimum key size in bits, zero implies no minimum size
	 *         limit.
	 */
	@Deprecated
	public int getMinSize() {

		return getMinKeySize();
	}


	/**
	 * Returns the minimum key size.
	 *
	 * @return The minimum key size in bits, zero implies no minimum size
	 *         limit.
	 */
	public int getMinKeySize() {

		return minSizeBits;
	}


	/**
	 * Returns the maximum key size. Use {@link #getMaxKeySize()} instead.
	 *
	 * @return The maximum key size in bits, zero implies no maximum size
	 *         limit.
	 */
	@Deprecated
	public int getMaxSize() {

		return getMaxKeySize();
	}


	/**
	 * Returns the maximum key size.
	 *
	 * @return The maximum key size in bits, zero implies no maximum size
	 *         limit.
	 */
	public int getMaxKeySize() {

		return maxSizeBits;
	}
	
	
	/**
	 * Returns the key sizes.
	 *
	 * @return The key sizes in bits, {@code null} if not specified.
	 */
	public Set<Integer> getKeySizes() {
		
		return sizesBits;
	}
	
	
	/**
	 * Returns the curves to match (for EC and OKP keys).
	 *
	 * @return The curves, {@code null} if not specified.
	 */
	public Set<Curve> getCurves() {
		
		return curves;
	}

	/**
	 * Returns the X.509 certificate SHA-256 thumbprints to match.
	 *
	 * @return The thumbprints, {@code null} if not specified.
	 */
	public Set<Base64URL> getX509CertSHA256Thumbprints() {
		
		return x5tS256s;
	}
	
	
	/**
	 * Returns {@code true} if keys with a specified X.509 certificate
	 * chain are matched.
	 *
	 * @return {@code true} if keys with a specified X.509 certificate are
	 *         matched, else {@code false}.
	 */
	@Deprecated
	public boolean hasX509CertChain() {
		
		return isWithX509CertChainOnly();
	}


	/**
	 * Returns {@code true} if keys with a specified X.509 certificate
	 * chain are matched.
	 *
	 * @return {@code true} if keys with a specified X.509 certificate
	 *         chain are matched, else {@code false}.
	 */
	public boolean isWithX509CertChainOnly() {

		return withX5COnly;
	}
	

	/**
	 * Returns {@code true} if the specified JWK matches.
	 *
	 * @param key The JSON Web Key (JWK). Must not  be {@code null}.
	 *
	 * @return {@code true} if the JWK matches, else {@code false}.
	 */
	public boolean matches(final JWK key) {
		
		if (withUseOnly && key.getKeyUse() == null)
			return false;
		
		if (withIDOnly && (key.getKeyID() == null || key.getKeyID().trim().isEmpty()))
			return false;

		if (privateOnly && ! key.isPrivate())
			return false;

		if (publicOnly && key.isPrivate())
			return false;

		if (nonRevokedOnly && key.getKeyRevocation() != null)
			return false;

		if (revokedOnly && key.getKeyRevocation() == null)
			return false;

		if (types != null && ! types.contains(key.getKeyType()))
			return false;

		if (uses != null && ! uses.contains(key.getKeyUse()))
			return false;

		if (ops != null) {

			if (ops.contains(null) && key.getKeyOperations() == null) {
				// pass
			} else if (key.getKeyOperations() != null && ops.containsAll(key.getKeyOperations())) {
				// pass
			} else {
				return false;
			}
		}

		if (algs != null && ! algs.contains(key.getAlgorithm()))
			return false;

		if (ids != null && ! ids.contains(key.getKeyID()))
			return false;

		if (minSizeBits > 0) {

			if (key.size() < minSizeBits)
				return false;
		}

		if (maxSizeBits > 0) {

			if (key.size() > maxSizeBits)
				return false;
		}
		
		if (sizesBits != null) {
			if (! sizesBits.contains(key.size()))
				return false;
		}
		
		if (curves != null) {
			
			if (! (key instanceof CurveBasedJWK))
				return false;
			
			CurveBasedJWK curveBasedJWK = (CurveBasedJWK) key;
			
			if (! curves.contains(curveBasedJWK.getCurve()))
				return false;
		}

		if (x5tS256s != null) {
			
			boolean matchingCertFound = false;
			
			if (key.getX509CertChain() != null && ! key.getX509CertChain().isEmpty()) {
				try {
					X509Certificate cert = X509CertUtils.parseWithException(key.getX509CertChain().get(0).decode());
					matchingCertFound = x5tS256s.contains(X509CertUtils.computeSHA256Thumbprint(cert));
				} catch (CertificateException e) {
					// Ignore
				}
			}
			
			boolean matchingX5T256Found = x5tS256s.contains(key.getX509CertSHA256Thumbprint());
			
			if (! matchingCertFound && ! matchingX5T256Found) {
				return false;
			}
		}
		
		if (withX5COnly) {
			return key.getX509CertChain() != null && !key.getX509CertChain().isEmpty();
		}

		return true;
	}
	
	
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		
		append(sb, JWKParameterNames.KEY_TYPE, types);
		append(sb, JWKParameterNames.PUBLIC_KEY_USE, uses);
		append(sb, JWKParameterNames.KEY_OPS, ops);
		append(sb, JWKParameterNames.ALGORITHM, algs);
		append(sb, JWKParameterNames.KEY_ID, ids);
		
		if (withUseOnly) {
			sb.append("with_use_only=true ");
		}
		
		if (withIDOnly) {
			sb.append("with_id_only=true ");
		}
		
		if (privateOnly) {
			sb.append("private_only=true ");
		}
		
		if (publicOnly) {
			sb.append("public_only=true ");
		}

		if (nonRevokedOnly) {
			sb.append("non_revoked_only=true ");
		}

		if (revokedOnly) {
			sb.append("revoked_only=true ");
		}
		
		if (minSizeBits > 0) {
			sb.append("min_size=" + minSizeBits + " ");
		}
		
		if (maxSizeBits > 0) {
			sb.append("max_size=" + maxSizeBits + " ");
		}
		
		append(sb, "size", sizesBits);
		append(sb, JWKParameterNames.ELLIPTIC_CURVE, curves);
		append(sb, JWKParameterNames.X_509_CERT_SHA_256_THUMBPRINT, x5tS256s);
		if (withX5COnly) {
			sb.append("with_x5c_only=true" );
		}
			
		return sb.toString().trim();
	}
	
	
	/**
	 * Appends the specified JWK matcher parameter to a string builder.
	 *
	 * @param sb     The string builder. Must not be {@code null}.
	 * @param key    The parameter key. Must not be {@code null}.
	 * @param values The parameter value, {@code null} if not specified.
	 */
	private static void append(final StringBuilder sb, final String key, final Set<?> values) {
		
		if (values != null) {
			
			sb.append(key);
			sb.append('=');
			if (values.size() == 1) {
				Object value = values.iterator().next();
				if (value == null) {
					sb.append("ANY");
				} else {
					sb.append(value.toString().trim());
				}
			} else {
				sb.append(values.toString().trim());
			}
			
			sb.append(' ');
		}
	}
}
