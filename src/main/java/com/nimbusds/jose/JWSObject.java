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


import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.StandardCharset;
import net.jcip.annotations.ThreadSafe;

import java.security.Signature;
import java.text.ParseException;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;


/**
 * JSON Web Signature (JWS) secured object with
 * <a href="https://datatracker.ietf.org/doc/html/rfc7515#section-7.1">compact
 * serialisation</a>.
 *
 * <p>This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version 2024-04-20
 */
@ThreadSafe
public class JWSObject extends JOSEObject {


	private static final long serialVersionUID = 1L;
	
	
	/**
	 * Enumeration of the states of a JSON Web Signature (JWS) secured
	 * object.
	 */
	public enum State {
		
		
		/**
		 * The object is not signed yet.
		 */
		UNSIGNED,
		
		
		/**
		 * The JWS secured object is signed but its signature is not
		 * verified.
		 */
		SIGNED,
		
		
		/**
		 * The JWS secured object is signed and its signature was
		 * successfully verified.
		 */
		VERIFIED
	}


	/**
	 * The header.
	 */
	private final JWSHeader header;


	/**
	 * The signing input for this JWS object.
	 */
	private final String signingInputString;


	/**
	 * The signature, {@code null} if not signed.
	 */
	private Base64URL signature;


	/**
	 * The JWS object state.
	 */
	private final AtomicReference<State> state = new AtomicReference<>();


	/**
	 * Creates a new to-be-signed JSON Web Signature (JWS) object with the 
	 * specified header and payload. The initial state will be 
	 * {@link State#UNSIGNED unsigned}.
	 *
	 * @param header  The JWS header. Must not be {@code null}.
	 * @param payload The payload. Must not be {@code null}.
	 */
	public JWSObject(final JWSHeader header, final Payload payload) {

		this.header = Objects.requireNonNull(header);
		setPayload(Objects.requireNonNull(payload));
		signingInputString = composeSigningInput();
		signature = null;
		state.set(State.UNSIGNED);
	}


	/**
	 * Creates a new signed JSON Web Signature (JWS) object with the
	 * specified serialised parts. The state will be
	 * {@link State#SIGNED signed}.
	 *
	 * @param firstPart  The first part, corresponding to the JWS header.
	 *                   Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the payload.
	 *                   Must not be {@code null}.
	 * @param thirdPart  The third part, corresponding to the signature.
	 *                   Must not be {@code null}.
	 *
	 * @throws ParseException If parsing of the serialised parts failed.
	 */
	public JWSObject(final Base64URL firstPart, final Base64URL secondPart, final Base64URL thirdPart)
		throws ParseException {
		this(firstPart, new Payload(secondPart), thirdPart);
	}

	
	/**
	 * Creates a new signed JSON Web Signature (JWS) object with the
	 * specified serialised parts and payload which can be optionally
	 * unencoded (RFC 7797). The state will be {@link State#SIGNED signed}.
	 *
	 * @param firstPart The first part, corresponding to the JWS header.
	 *                  Must not be {@code null}.
	 * @param payload   The payload. Must not be {@code null}.
	 * @param thirdPart The third part, corresponding to the signature.
	 *                  Must not be {@code null}.
	 *
	 * @throws ParseException If parsing of the serialised parts failed.
	 */
	public JWSObject(final Base64URL firstPart, final Payload payload, final Base64URL thirdPart)
		throws ParseException {

		try {
			this.header = JWSHeader.parse(firstPart);
		} catch (ParseException e) {
			throw new ParseException("Invalid JWS header: " + e.getMessage(), 0);
		}

		setPayload(Objects.requireNonNull(payload));
		
		signingInputString = composeSigningInput();

		if (thirdPart.toString().trim().isEmpty()) {
			throw new ParseException("The signature must not be empty", 0);
		}
		
		signature = thirdPart;
		state.set(State.SIGNED); // but signature not verified yet!

		if (getHeader().isBase64URLEncodePayload()) {
			setParsedParts(firstPart, payload.toBase64URL(), thirdPart);
		} else {
			setParsedParts(firstPart, new Base64URL(""), thirdPart);
		}
	}

	@Override
	public JWSHeader getHeader() {

		return header;
	}


	/**
	 * Composes the signing input string from the header and payload.
	 *
	 * @return The signing input string.
	 */
	private String composeSigningInput() {
		
		if (header.isBase64URLEncodePayload()) {
			return getHeader().toBase64URL().toString() + '.' + getPayload().toBase64URL().toString();
		} else {
			return getHeader().toBase64URL().toString() + '.' + getPayload().toString();
		}
	}


	/**
	 * Returns the signing input for this JWS object.
	 *
	 * @return The signing input, to be passed to a JWS signer or verifier.
	 */
	public byte[] getSigningInput() {
		
		return signingInputString.getBytes(StandardCharset.UTF_8);
	}


	/**
	 * Returns the signature of this JWS object.
	 *
	 * @return The signature, {@code null} if the JWS object is not signed 
	 *         yet.
	 */
	public Base64URL getSignature() {

		return signature;
	}
	
	
	/**
	 * Returns the state of the JWS secured object.
	 *
	 * @return The state.
	 */
	public State getState() {

		return state.get();
	}


	/**
	 * Ensures the current state is {@link State#UNSIGNED unsigned}.
	 *
	 * @throws IllegalStateException If the current state is not unsigned.
	 */
	private void ensureUnsignedState() {

		if (state.get() != State.UNSIGNED) {

			throw new IllegalStateException("The JWS object must be in an unsigned state");
		}
	}


	/**
	 * Ensures the current state is {@link State#SIGNED signed} or
	 * {@link State#VERIFIED verified}.
	 *
	 * @throws IllegalStateException If the current state is not signed or
	 *                               verified.
	 */
	private void ensureSignedOrVerifiedState() {

		if (state.get() != State.SIGNED && state.get() != State.VERIFIED) {

			throw new IllegalStateException("The JWS object must be in a signed or verified state");
		}
	}


	/**
	 * Ensures the specified JWS signer supports the algorithm of this JWS
	 * object.
	 *
	 * @throws JOSEException If the JWS algorithm is not supported.
	 */
	private void ensureJWSSignerSupport(final JWSSigner signer)
		throws JOSEException {

		if (! signer.supportedJWSAlgorithms().contains(getHeader().getAlgorithm())) {

			throw new JOSEException("The " + getHeader().getAlgorithm() +
			                        " algorithm is not allowed or supported by the JWS signer: Supported algorithms: " + signer.supportedJWSAlgorithms());
		}
	}


	/**
	 * Signs this JWS object with the specified signer. The JWS object must
	 * be in a {@link State#UNSIGNED unsigned} state.
	 *
	 * @param signer The JWS signer. Must not be {@code null}.
	 *
	 * @throws IllegalStateException If the JWS object is not in an 
	 *                               {@link State#UNSIGNED unsigned state}.
	 * @throws JOSEException         If the JWS object couldn't be signed.
	 */
	public synchronized void sign(final JWSSigner signer)
		throws JOSEException {

		ensureUnsignedState();

		ensureJWSSignerSupport(signer);

		try {
			signature = signer.sign(getHeader(), getSigningInput());
			
		} catch (final ActionRequiredForJWSCompletionException e) {
			// Catch to enable state SIGNED update
			throw new ActionRequiredForJWSCompletionException(
				e.getMessage(),
				e.getTriggeringOption(),
				new CompletableJWSObjectSigning() {

					@Override
					public Signature getInitializedSignature() {
						return e.getCompletableJWSObjectSigning().getInitializedSignature();
					}

					@Override
					public Base64URL complete() throws JOSEException {
						signature = e.getCompletableJWSObjectSigning().complete();
						state.set(State.SIGNED);
						return signature;
					}
				}
			);

		} catch (JOSEException e) {

			throw e;
				
		} catch (Exception e) {

			// Prevent throwing unchecked exceptions at this point,
			// see issue #20
			throw new JOSEException(e.getMessage(), e);
		}

		state.set(State.SIGNED);
	}


	/**
	 * Checks the signature of this JWS object with the specified verifier.
	 * The JWS object must be in a {@link State#SIGNED signed} state.
	 *
	 * @param verifier The JWS verifier. Must not be {@code null}.
	 *
	 * @return {@code true} if the signature was successfully verified,
	 *         else {@code false}.
	 *
	 * @throws IllegalStateException If the JWS object is not in a
	 *                               {@link State#SIGNED signed} or
	 *                               {@link State#VERIFIED verified state}.
	 * @throws JOSEException         If the JWS object couldn't be
	 *                               verified.
	 */
	public synchronized boolean verify(final JWSVerifier verifier)
		throws JOSEException {

		ensureSignedOrVerifiedState();

		boolean verified;

		try {
			verified = verifier.verify(getHeader(), getSigningInput(), getSignature());

		} catch (JOSEException e) {

			throw e;

		} catch (Exception e) {

			// Prevent throwing unchecked exceptions at this point,
			// see issue #20
			throw new JOSEException(e.getMessage(), e);
		}

		if (verified) {

			state.set(State.VERIFIED);
		}

		return verified;
	}


	/**
	 * Serialises this JWS object to its compact format consisting of 
	 * Base64URL-encoded parts delimited by period ('.') characters. It 
	 * must be in a {@link State#SIGNED signed} or 
	 * {@link State#VERIFIED verified} state.
	 *
	 * <pre>
	 * [header-base64url].[payload-base64url].[signature-base64url]
	 * </pre>
	 *
	 * @return The serialised JWS object.
	 *
	 * @throws IllegalStateException If the JWS object is not in a 
	 *                               {@link State#SIGNED signed} or
	 *                               {@link State#VERIFIED verified} state.
	 */
	@Override
	public String serialize() {
		return serialize(false);
	}


	/**
	 * Serialises this JWS object to its compact format consisting of
	 * Base64URL-encoded parts delimited by period ('.') characters. It
	 * must be in a {@link State#SIGNED signed} or
	 * {@link State#VERIFIED verified} state.
	 *
	 * @param detachedPayload {@code true} to return a serialised object
	 *                        with a detached payload compliant with RFC
	 *                        7797, {@code false} for regular JWS
	 *                        serialisation.
	 *
	 * @return The serialised JOSE object.
	 *
	 * @throws IllegalStateException If the JOSE object is not in a state
	 *                               that permits serialisation.
	 */
	public String serialize(final boolean detachedPayload) {
		ensureSignedOrVerifiedState();

		if (detachedPayload) {
			return header.toBase64URL().toString() + '.' + '.' + signature.toString();
		}

		return signingInputString + '.' + signature.toString();
	}

	
	/**
	 * Parses a JWS object from the specified string in compact format. The
	 * parsed JWS object will be given a {@link State#SIGNED} state.
	 *
	 * @param s The JWS string to parse. Must not be {@code null}.
	 *
	 * @return The JWS object.
	 *
	 * @throws ParseException If the string couldn't be parsed to a JWS
	 *                        object.
	 */
	public static JWSObject parse(final String s)
		throws ParseException {

		Base64URL[] parts = JOSEObject.split(s);

		if (parts.length != 3) {

			throw new ParseException("Unexpected number of Base64URL parts, must be three", 0);
		}

		return new JWSObject(parts[0], parts[1], parts[2]);
	}
	
	
	/**
	 * Parses a JWS object from the specified string in compact format and
	 * a detached payload which can be optionally unencoded (RFC 7797). The
	 * parsed JWS object will be given a {@link State#SIGNED} state.
	 *
	 * @param s               The JWS string to parse for a detached
	 *                        payload. Must not be {@code null}.
	 * @param detachedPayload The detached payload, optionally unencoded
	 *                        (RFC 7797). Must not be {@code null}.
	 *
	 * @return The JWS object.
	 *
	 * @throws ParseException If the string couldn't be parsed to a JWS
	 *                        object.
	 */
	public static JWSObject parse(final String s, final Payload detachedPayload)
		throws ParseException {
		
		Base64URL[] parts = JOSEObject.split(s);
		
		if (parts.length != 3) {
			throw new ParseException("Unexpected number of Base64URL parts, must be three", 0);
		}
		
		if (! parts[1].toString().isEmpty()) {
			throw new ParseException("The payload Base64URL part must be empty", 0);
		}
		
		return new JWSObject(parts[0], detachedPayload, parts[2]);
	}
}
