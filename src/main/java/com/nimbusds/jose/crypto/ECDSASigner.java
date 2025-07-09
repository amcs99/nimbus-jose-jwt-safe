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


import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.util.Collections;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.impl.AlgorithmSupportMessage;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.crypto.impl.ECDSAProvider;
import com.nimbusds.jose.crypto.opts.OptionUtils;
import com.nimbusds.jose.crypto.opts.UserAuthenticationRequired;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;


/**
 * Elliptic Curve Digital Signature Algorithm (ECDSA) signer of
 * {@link com.nimbusds.jose.JWSObject JWS objects}. Expects a private EC key
 * (with a P-256, P-384, P-521 or secp256k1 curve).
 *
 * <p>See RFC 7518
 * <a href="https://tools.ietf.org/html/rfc7518#section-3.4">section 3.4</a>
 * for more information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES256K}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#ES512}
 * </ul>
 *
 * <p>Supports the following {@link JWSSignerOption options}:
 *
 * <ul>
 *     <li>{@link UserAuthenticationRequired} -- to prompt the user to
 *         authenticate in order to complete the signing operation. Android
 *         applications can use this option to trigger a biometric prompt that
 *         is required to unlock a private key created with
 *         {@code setUserAuthenticationRequired(true)}.
 * </ul>
 *
 * @author Axel Nennker
 * @author Vladimir Dzhuvinov
 * @version 2023-04-20
 */
@ThreadSafe
public class ECDSASigner extends ECDSAProvider implements JWSSigner {


	/**
	 * The private EC key. Represented by generic private key interface to
	 * support key stores that prevent exposure of the private key
	 * parameters via the {@link java.security.interfaces.ECPrivateKey}
	 * API.
	 *
	 * See https://bitbucket.org/connect2id/nimbus-jose-jwt/issues/169
	 */
	private final PrivateKey privateKey;


	/**
	 * The configured options, empty set if none.
	 */
	private final Set<JWSSignerOption> opts;


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
	 * signer.
	 *
	 * @param privateKey The private EC key. Must not be {@code null}.
	 *
	 * @throws JOSEException If the elliptic curve of key is not supported.
	 */
	public ECDSASigner(final ECPrivateKey privateKey)
		throws JOSEException {

		this(privateKey, (Set<JWSSignerOption>) null);
	}


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
	 * signer.
	 *
	 * @param privateKey The private EC key. Must not be {@code null}.
	 * @param opts       The signing options, empty or {@code null} if
	 *                   none.
	 *
	 * @throws JOSEException If the elliptic curve of key is not supported.
	 */
	public ECDSASigner(final ECPrivateKey privateKey, final Set<JWSSignerOption> opts)
			throws JOSEException {

		super(ECDSA.resolveAlgorithm(privateKey));

		this.privateKey = privateKey;
		this.opts = opts != null ? opts : Collections.<JWSSignerOption>emptySet();
	}


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
	 * signer. This constructor is intended for a private EC key located
	 * in a PKCS#11 store that doesn't expose the private key parameters
	 * (such as a smart card or HSM).
	 *
	 * @param privateKey The private EC key. Its algorithm must be "EC".
	 *                   Must not be {@code null}.
	 * @param curve      The elliptic curve for the key. Must not be
	 *                   {@code null}.
	 *
	 * @throws JOSEException If the elliptic curve of key is not supported.
	 */
	public ECDSASigner(final PrivateKey privateKey, final Curve curve)
		throws JOSEException {
		this(privateKey, curve, null);
	}


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
	 * signer. This constructor is intended for a private EC key located
	 * in a PKCS#11 store that doesn't expose the private key parameters
	 * (such as a smart card or HSM).
	 *
	 * @param privateKey The private EC key. Its algorithm must be "EC".
	 *                   Must not be {@code null}.
	 * @param curve      The elliptic curve for the key. Must not be
	 *                   {@code null}.
	 * @param opts       The signing options, empty or {@code null} if
	 *                   none.
	 *
	 * @throws JOSEException If the elliptic curve of key is not supported.
	 */
	public ECDSASigner(final PrivateKey privateKey, final Curve curve, final Set<JWSSignerOption> opts)
			throws JOSEException {

		super(ECDSA.resolveAlgorithm(curve));

		if (! "EC".equalsIgnoreCase(privateKey.getAlgorithm())) {
			throw new IllegalArgumentException("The private key algorithm must be EC");
		}

		this.privateKey = privateKey;
		this.opts = opts != null ? opts : Collections.<JWSSignerOption>emptySet();
	}


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
	 * signer.
	 *
	 * @param ecJWK The EC JSON Web Key (JWK). Must contain a private part.
	 *              Must not be {@code null}.
	 *
	 * @throws JOSEException If the EC JWK doesn't contain a private part,
	 *                       its extraction failed, or the elliptic curve
	 *                       is not supported.
	 */
	public ECDSASigner(final ECKey ecJWK)
		throws JOSEException {
		this(ecJWK, null);
	}


	/**
	 * Creates a new Elliptic Curve Digital Signature Algorithm (ECDSA)
	 * signer.
	 *
	 * @param ecJWK The EC JSON Web Key (JWK). Must contain a private part.
	 *              Must not be {@code null}.
	 * @param opts  The signing options, empty or {@code null} if
	 *              none.
	 *
	 * @throws JOSEException If the EC JWK doesn't contain a private part,
	 *                       its extraction failed, or the elliptic curve
	 *                       is not supported.
	 */
	public ECDSASigner(final ECKey ecJWK, final Set<JWSSignerOption> opts)
			throws JOSEException {

		super(ECDSA.resolveAlgorithm(ecJWK.getCurve()));

		if (! ecJWK.isPrivate()) {
			throw new JOSEException("The EC JWK doesn't contain a private part");
		}

		privateKey = ecJWK.toPrivateKey();
		this.opts = opts != null ? opts : Collections.<JWSSignerOption>emptySet();
	}


	/**
	 * Gets the private EC key.
	 *
	 * @return The private EC key. Casting to
	 *         {@link java.security.interfaces.ECPrivateKey} may not be
	 *         possible if the key is located in a PKCS#11 store that
	 *         doesn't expose the private key parameters.
	 */
	public PrivateKey getPrivateKey() {

		return privateKey;
	}


	@Override
	public Base64URL sign(final JWSHeader header, final byte[] signingInput)
		throws JOSEException {

		final JWSAlgorithm alg = header.getAlgorithm();

		if (! supportedJWSAlgorithms().contains(alg)) {
			throw new JOSEException(AlgorithmSupportMessage.unsupportedJWSAlgorithm(alg, supportedJWSAlgorithms()));
		}

		// DER-encoded signature, according to JCA spec
		final byte[] jcaSignature;
		try {
			final Signature dsa = ECDSA.getSignerAndVerifier(alg, getJCAContext().getProvider());
			dsa.initSign(privateKey, getJCAContext().getSecureRandom());

			if (OptionUtils.optionIsPresent(opts, UserAuthenticationRequired.class)) {

				throw new ActionRequiredForJWSCompletionException(
						"Authenticate user to complete signing",
						UserAuthenticationRequired.getInstance(),
						new CompletableJWSObjectSigning() {
							@Override
							public Signature getInitializedSignature() {
								return dsa;
							}

							@Override
							public Base64URL complete() throws JOSEException {

								try {
									dsa.update(signingInput);
									final byte[] jcaSignature = dsa.sign();
									final int rsByteArrayLength = ECDSA.getSignatureByteArrayLength(header.getAlgorithm());
									final byte[] jwsSignature = ECDSA.transcodeSignatureToConcat(jcaSignature, rsByteArrayLength);
									return Base64URL.encode(jwsSignature);
								} catch (SignatureException e) {

								throw new JOSEException(e.getMessage(), e);
								}
							}
						}
				);
			}
			dsa.update(signingInput);
			jcaSignature = dsa.sign();

		} catch (InvalidKeyException | SignatureException e) {

			throw new JOSEException(e.getMessage(), e);
		}

		final int rsByteArrayLength = ECDSA.getSignatureByteArrayLength(header.getAlgorithm());
		final byte[] jwsSignature = ECDSA.transcodeSignatureToConcat(jcaSignature, rsByteArrayLength);
		return Base64URL.encode(jwsSignature);
	}
}
