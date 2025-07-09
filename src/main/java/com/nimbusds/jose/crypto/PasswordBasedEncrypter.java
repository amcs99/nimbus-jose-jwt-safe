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
import com.nimbusds.jose.crypto.impl.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StandardCharset;
import net.jcip.annotations.ThreadSafe;

import javax.crypto.SecretKey;
import java.util.Arrays;


/**
 * Password-based encrypter of {@link com.nimbusds.jose.JWEObject JWE objects}.
 * Expects a password.
 *
 * <p>See RFC 7518
 * <a href="https://tools.ietf.org/html/rfc7518#section-4.8">section 4.8</a>
 * for more information.
 *
 * <p>This class is thread-safe.
 *
 * <p>Supports the following key management algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#PBES2_HS256_A128KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#PBES2_HS384_A192KW}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#PBES2_HS512_A256KW}
 * </ul>
 *
 * <p>Supports the following content encryption algorithms:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#XC20P}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @author Egor Puzanov
 * @version 2024-09-10
 */
@ThreadSafe
public class PasswordBasedEncrypter extends PasswordBasedCryptoProvider implements JWEEncrypter {


	/**
	 * The minimum salt length (8 bytes).
	 */
	public static final int MIN_SALT_LENGTH = PBKDF2.MIN_SALT_LENGTH;


	/**
	 * The cryptographic salt length, in bytes.
	 */
	private final int saltLength;


	/**
	 * The minimum recommended iteration count (1000).
	 */
	public static final int MIN_RECOMMENDED_ITERATION_COUNT = 1000;


	/**
	 * The iteration count.
	 */
	private final int iterationCount;


	/**
	 * Creates a new password-based encrypter.
	 *
	 * @param password       The password bytes. Must not be empty or
	 *                       {@code null}.
	 * @param saltLength     The length of the generated cryptographic
	 *                       salts, in bytes. Must be at least 8 bytes.
	 * @param iterationCount The pseudo-random function (PRF) iteration
	 *                       count. Must be at least 1000.
	 */
	public PasswordBasedEncrypter(final byte[] password,
				      final int saltLength,
				      final int iterationCount) {

		super(password);

		if (saltLength < MIN_SALT_LENGTH) {
			throw new IllegalArgumentException("The minimum salt length (p2s) is " + MIN_SALT_LENGTH + " bytes");
		}

		this.saltLength = saltLength;

		if (iterationCount < MIN_RECOMMENDED_ITERATION_COUNT) {
			throw new IllegalArgumentException("The minimum recommended iteration count (p2c) is " + MIN_RECOMMENDED_ITERATION_COUNT);
		}

		this.iterationCount = iterationCount;
	}


	/**
	 * Creates a new password-based encrypter.
	 *
	 * @param password       The password, as a UTF-8 encoded string. Must
	 *                       not be empty or {@code null}.
	 * @param saltLength     The length of the generated cryptographic
	 *                       salts, in bytes. Must be at least 8 bytes.
	 * @param iterationCount The pseudo-random function (PRF) iteration
	 *                       count. Must be at least 1000.
	 */
	public PasswordBasedEncrypter(final String password,
				      final int saltLength,
				      final int iterationCount) {

		this(password.getBytes(StandardCharset.UTF_8), saltLength, iterationCount);
	}


	/**
	 * Encrypts the specified clear text of a {@link JWEObject JWE object}.
	 *
	 * @param header    The JSON Web Encryption (JWE) header. Must specify
	 *                  a supported JWE algorithm and method. Must not be
	 *                  {@code null}.
	 * @param clearText The clear text to encrypt. Must not be {@code null}.
	 *
	 * @return The resulting JWE crypto parts.
	 *
	 * @throws JOSEException If the JWE algorithm or method is not
	 *                       supported or if encryption failed for some
	 *                       other internal reason.
	 */
	@Deprecated
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText)
		throws JOSEException {

		return encrypt(header, clearText, AAD.compute(header));
	}


	@Override
	public JWECryptoParts encrypt(final JWEHeader header, final byte[] clearText, final byte[] aad)
		throws JOSEException {

		final JWEAlgorithm alg = JWEHeaderValidation.getAlgorithmAndEnsureNotNull(header);
		final EncryptionMethod enc = header.getEncryptionMethod();

		final byte[] salt = new byte[saltLength];
		getJCAContext().getSecureRandom().nextBytes(salt);
		final byte[] formattedSalt = PBKDF2.formatSalt(alg, salt);
		final PRFParams prfParams = PRFParams.resolve(alg, getJCAContext().getMACProvider());
		final SecretKey psKey = PBKDF2.deriveKey(getPassword(), formattedSalt, iterationCount, prfParams, getJCAContext().getProvider());

		// We need to work on the header
		final JWEHeader updatedHeader = new JWEHeader.Builder(header).
			pbes2Salt(Base64URL.encode(salt)).
			pbes2Count(iterationCount).
			build();

		final SecretKey cek = ContentCryptoProvider.generateCEK(enc, getJCAContext().getSecureRandom());

		// The second JWE part
		final Base64URL encryptedKey = Base64URL.encode(AESKW.wrapCEK(cek, psKey, getJCAContext().getKeyEncryptionProvider()));

		// for JWEObject we need update the AAD as well
		final byte[] updatedAAD = Arrays.equals(AAD.compute(header), aad) ? AAD.compute(updatedHeader) : aad;

		return ContentCryptoProvider.encrypt(updatedHeader, clearText, updatedAAD, cek, encryptedKey, getJCAContext());
	}


	/**
	 * Returns the length of the generated cryptographic salts.
	 *
	 * @return The length of the generated cryptographic salts, in bytes.
	 */
	public int getSaltLength() {

		return saltLength;
	}


	/**
	 * Returns the pseudo-random function (PRF) iteration count.
	 *
	 * @return The iteration count.
	 */
	public int getIterationCount() {

		return iterationCount;
	}
}
