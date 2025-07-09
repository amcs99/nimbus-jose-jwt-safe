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

package com.nimbusds.jose;


import com.nimbusds.jose.crypto.impl.AAD;
import com.nimbusds.jose.util.Base64URL;
import net.jcip.annotations.ThreadSafe;

import java.text.ParseException;
import java.util.Objects;


/**
 * JSON Web Encryption (JWE) secured object with
 * <a href="https://datatracker.ietf.org/doc/html/rfc7516#section-7.1">compact
 * serialisation</a>.
 *
 * <p>This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @author Egor Puzanov
 * @version 2025-05-08
 */
@ThreadSafe
public class JWEObject extends JOSEObject {


	private static final long serialVersionUID = 1L;


	/**
	 * The maximum allowed character length of compressed cipher text.
	 */
	public static final int MAX_COMPRESSED_CIPHER_TEXT_LENGTH = 100_000;
	
	
	/**
	 * Enumeration of the states of a JSON Web Encryption (JWE) secured
	 * object.
	 */
	public enum State {
		
		
		/**
		 * The JWE secured object is created but not encrypted yet.
		 */
		UNENCRYPTED,
		
		
		/**
		 * The JWE secured object is encrypted.
		 */
		ENCRYPTED,
		
		
		/**
		 * The JWE secured object is decrypted.
		 */
		DECRYPTED
	}


	/**
	 * The header.
	 */
	private JWEHeader header;


	/** 
	 * The encrypted key, {@code null} if not computed or applicable.
	 */
	private Base64URL encryptedKey;


	/**
	 * The initialisation vector, {@code null} if not generated or 
	 * applicable.
	 */
	private Base64URL iv;


	/**
	 * The cipher text, {@code null} if not computed.
	 */
	private Base64URL cipherText;


	/**
	 * The authentication tag, {@code null} if not computed or applicable.
	 */
	private Base64URL authTag;


	/**
	 * The JWE object state.
	 */
	private State state;


	/**
	 * Creates a new to-be-encrypted JSON Web Encryption (JWE) object with 
	 * the specified header and payload. The initial state will be 
	 * {@link State#UNENCRYPTED unencrypted}.
	 *
	 * @param header  The JWE header. Must not be {@code null}.
	 * @param payload The payload. Must not be {@code null}.
	 */
	public JWEObject(final JWEHeader header, final Payload payload) {

		this.header = Objects.requireNonNull(header);
		setPayload(Objects.requireNonNull(payload));
		encryptedKey = null;
		cipherText = null;
		state = State.UNENCRYPTED;
	}


	/**
	 * Creates a new encrypted JSON Web Encryption (JWE) object with the 
	 * specified serialised parts. The state will be {@link State#ENCRYPTED 
	 * encrypted}.
	 *
	 * @param firstPart  The first part, corresponding to the JWE header. 
	 *                   Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the encrypted 
	 *                   key. Empty or {@code null} if none.
	 * @param thirdPart  The third part, corresponding to the 
	 *                   initialisation vector. Empty or {@code null} if 
	 *                   none.
	 * @param fourthPart The fourth part, corresponding to the cipher text.
	 *                   Must not be {@code null}.
	 * @param fifthPart  The fifth part, corresponding to the 
	 *                   authentication tag. Empty of {@code null} if none.
	 *
	 * @throws ParseException If parsing of the serialised parts failed.
	 */
	public JWEObject(final Base64URL firstPart, 
		         final Base64URL secondPart, 
		         final Base64URL thirdPart,
		         final Base64URL fourthPart,
		         final Base64URL fifthPart)
		throws ParseException {

		try {
			this.header = JWEHeader.parse(Objects.requireNonNull(firstPart));
		} catch (ParseException e) {
			throw new ParseException("Invalid JWE header: " + e.getMessage(), 0);
		}

		if (secondPart == null || secondPart.toString().isEmpty()) {

			encryptedKey = null;

		} else {

			encryptedKey = secondPart;
		}

		if (thirdPart == null || thirdPart.toString().isEmpty()) {

			iv = null;

		} else {

			iv = thirdPart;
		}

		cipherText = Objects.requireNonNull(fourthPart);

		if (fifthPart == null || fifthPart.toString().isEmpty()) {

			authTag = null;

		} else {

			authTag = fifthPart;
		}

		state = State.ENCRYPTED; // but not decrypted yet!

		setParsedParts(firstPart, secondPart, thirdPart, fourthPart, fifthPart);
	}


	@Override
	public JWEHeader getHeader() {

		return header;
	}


	/**
	 * Returns the encrypted key of this JWE object.
	 *
	 * @return The encrypted key, {@code null} not applicable or the JWE
	 *         object has not been encrypted yet.
	 */
	public Base64URL getEncryptedKey() {

		return encryptedKey;
	}


	/**
	 * Returns the initialisation vector (IV) of this JWE object.
	 *
	 * @return The initialisation vector (IV), {@code null} if not 
	 *         applicable or the JWE object has not been encrypted yet.
	 */
	public Base64URL getIV() {

		return iv;
	}


	/**
	 * Returns the cipher text of this JWE object.
	 *
	 * @return The cipher text, {@code null} if the JWE object has not been
	 *         encrypted yet.
	 */
	public Base64URL getCipherText() {

		return cipherText;
	}


	/**
	 * Returns the authentication tag of this JWE object.
	 *
	 * @return The authentication tag, {@code null} if not applicable or
	 *         the JWE object has not been encrypted yet.
	 */
	public Base64URL getAuthTag() {

		return authTag;
	}
	
	
	/**
	 * Returns the state of the JWE secured object.
	 *
	 * @return The state.
	 */
	public State getState() {

		return state;
	}


	/**
	 * Ensures the current state is {@link State#UNENCRYPTED unencrypted}.
	 *
	 * @throws IllegalStateException If the current state is not 
	 *                               unencrypted.
	 */
	private void ensureUnencryptedState() {

		if (state != State.UNENCRYPTED) {

			throw new IllegalStateException("The JWE object must be in an unencrypted state");
		}
	}


	/**
	 * Ensures the current state is {@link State#ENCRYPTED encrypted}.
	 *
	 * @throws IllegalStateException If the current state is not encrypted.
	 */
	private void ensureEncryptedState() {

		if (state != State.ENCRYPTED) {

			throw new IllegalStateException("The JWE object must be in an encrypted state");
		}
	}


	/**
	 * Ensures the current state is {@link State#ENCRYPTED encrypted} or
	 * {@link State#DECRYPTED decrypted}.
	 *
	 * @throws IllegalStateException If the current state is not encrypted 
	 *                               or decrypted.
	 */
	private void ensureEncryptedOrDecryptedState() {

		if (state != State.ENCRYPTED && state != State.DECRYPTED) {

			throw new IllegalStateException("The JWE object must be in an encrypted or decrypted state");
		}
	}


	/**
	 * Ensures the specified JWE encrypter supports the algorithms of this 
	 * JWE object.
	 *
	 * @throws JOSEException If the JWE algorithms are not supported.
	 */
	private void ensureJWEEncrypterSupport(final JWEEncrypter encrypter)
		throws JOSEException {

		if (! encrypter.supportedJWEAlgorithms().contains(getHeader().getAlgorithm())) {

			throw new JOSEException("The " + getHeader().getAlgorithm() +
					        " algorithm is not supported by the JWE encrypter: Supported algorithms: " + encrypter.supportedJWEAlgorithms());
		}

		if (! encrypter.supportedEncryptionMethods().contains(getHeader().getEncryptionMethod())) {

			throw new JOSEException("The " + getHeader().getEncryptionMethod() +
					        " encryption method or key size is not supported by the JWE encrypter: Supported methods: " + encrypter.supportedEncryptionMethods());
		}
	}


	/**
	 * Encrypts this JWE object with the specified encrypter. The JWE 
	 * object must be in an {@link State#UNENCRYPTED unencrypted} state.
	 *
	 * @param encrypter The JWE encrypter. Must not be {@code null}.
	 *
	 * @throws IllegalStateException If the JWE object is not in an 
	 *                               {@link State#UNENCRYPTED unencrypted
	 *                               state}.
	 * @throws JOSEException         If the JWE object couldn't be 
	 *                               encrypted.
	 */
	public synchronized void encrypt(final JWEEncrypter encrypter)
		throws JOSEException {

		ensureUnencryptedState();

		ensureJWEEncrypterSupport(encrypter);

		JWECryptoParts parts;

		try {
			parts = encrypter.encrypt(getHeader(), getPayload().toBytes(), AAD.compute(getHeader()));

		} catch (JOSEException e) {

			throw e;
		
		} catch (Exception e) {

			// Prevent throwing unchecked exceptions at this point,
			// see issue #20
			throw new JOSEException(e.getMessage(), e);
		}

		// Check if the header has been modified
		if (parts.getHeader() != null) {
			header = parts.getHeader();
		}

		encryptedKey = parts.getEncryptedKey();
		iv = parts.getInitializationVector();
		cipherText = parts.getCipherText();
		authTag = parts.getAuthenticationTag();

		state = State.ENCRYPTED;
	}


	/**
	 * Decrypts this JWE object with the specified decrypter. The JWE 
	 * object must be in a {@link State#ENCRYPTED encrypted} state.
	 *
	 * @param decrypter The JWE decrypter. Must not be {@code null}.
	 *
	 * @throws IllegalStateException If the JWE object is not in an 
	 *                               {@link State#ENCRYPTED encrypted
	 *                               state}.
	 * @throws JOSEException         If the JWE object couldn't be 
	 *                               decrypted.
	 */
	public synchronized void decrypt(final JWEDecrypter decrypter)
		throws JOSEException {

		ensureEncryptedState();

		if (getHeader().getCompressionAlgorithm() != null &&
		    getCipherText().toString().length() > MAX_COMPRESSED_CIPHER_TEXT_LENGTH) {

			throw new JOSEException(
				"The JWE compressed cipher text exceeds the " +
				"maximum allowed length of " +
				MAX_COMPRESSED_CIPHER_TEXT_LENGTH +
				" characters");
		}

		try {
			setPayload(new Payload(decrypter.decrypt(getHeader(), 
					       getEncryptedKey(), 
					       getIV(),
					       getCipherText(), 
					       getAuthTag(),
					       AAD.compute(getHeader()))));

		} catch (JOSEException e) {

			throw e;

		} catch (Exception e) {

			// Prevent throwing unchecked exceptions at this point,
			// see issue #20
			throw new JOSEException(e.getMessage(), e);
		}

		state = State.DECRYPTED;
	}


	/**
	 * Serialises this JWE object to its compact format consisting of 
	 * Base64URL-encoded parts delimited by period ('.') characters. It 
	 * must be in a {@link State#ENCRYPTED encrypted} or 
	 * {@link State#DECRYPTED decrypted} state.
	 *
	 * <pre>
	 * [header-base64url].[encryptedKey-base64url].[iv-base64url].[cipherText-base64url].[authTag-base64url]
	 * </pre>
	 *
	 * @return The serialised JWE object.
	 *
	 * @throws IllegalStateException If the JWE object is not in a 
	 *                               {@link State#ENCRYPTED encrypted} or
	 *                               {@link State#DECRYPTED decrypted 
	 *                               state}.
	 */
	@Override
	public String serialize() {

		ensureEncryptedOrDecryptedState();

		StringBuilder sb = new StringBuilder(header.toBase64URL().toString());
		sb.append('.');

		if (encryptedKey != null) {
			sb.append(encryptedKey);
		}

		sb.append('.');

		if (iv != null) {
			sb.append(iv);
		}

		sb.append('.');
		sb.append(cipherText);
		sb.append('.');

		if (authTag != null) {
			sb.append(authTag);
		}

		return sb.toString();
	}


	/**
	 * Parses a JWE object from the specified string in compact form. The 
	 * parsed JWE object will be given an {@link State#ENCRYPTED} state.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The JWE object.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        JWE object.
	 */
	public static JWEObject parse(final String s)
		throws ParseException {

		Base64URL[] parts = JOSEObject.split(s);

		if (parts.length != 5) {

			throw new ParseException("Unexpected number of Base64URL parts, must be five", 0);
		}

		return new JWEObject(parts[0], parts[1], parts[2], parts[3], parts[4]);
	}
}
