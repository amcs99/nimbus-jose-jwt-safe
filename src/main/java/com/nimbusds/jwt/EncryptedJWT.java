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


import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;
import net.jcip.annotations.ThreadSafe;

import java.text.ParseException;
import java.util.Map;


/**
 * Encrypted JSON Web Token (JWT). This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version 2024-06-06
 */
@ThreadSafe
public class EncryptedJWT extends JWEObject implements JWT {


	private static final long serialVersionUID = 1L;

	/**
	 * The JWT claims set.
	 */
	private JWTClaimsSet claimsSet;


	/**
	 * Creates a new to-be-encrypted JSON Web Token (JWT) with the specified
	 * header and claims set. The initial state will be 
	 * {@link com.nimbusds.jose.JWEObject.State#UNENCRYPTED unencrypted}.
	 *
	 * @param header    The JWE header. Must not be {@code null}.
	 * @param claimsSet The JWT claims set. Must not be {@code null}.
	 */
	public EncryptedJWT(final JWEHeader header, final JWTClaimsSet claimsSet) {

		super(header, claimsSet.toPayload());
		this.claimsSet = claimsSet;
	}


	/**
	 * Creates a new encrypted JSON Web Token (JWT) with the specified 
	 * serialised parts. The state will be 
	 * {@link com.nimbusds.jose.JWEObject.State#ENCRYPTED encrypted}.
	 *
	 * @param firstPart  The first part, corresponding to the JWE header. 
	 *                   Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the encrypted 
	 *                   key. Empty or {@code null} if none.
	 * @param thirdPart  The third part, corresponding to the initialisation
	 *                   vectory. Empty or {@code null} if none.
	 * @param fourthPart The fourth part, corresponding to the cipher text.
	 *                   Must not be {@code null}.
	 * @param fifthPart  The fifth part, corresponding to the integrity
	 *                   value. Empty of {@code null} if none.
	 *
	 * @throws ParseException If parsing of the serialised parts failed.
	 */
	public EncryptedJWT(final Base64URL firstPart, 
			    final Base64URL secondPart, 
			    final Base64URL thirdPart,
			    final Base64URL fourthPart,
			    final Base64URL fifthPart)
		throws ParseException {

		super(firstPart, secondPart, thirdPart, fourthPart, fifthPart);
	}


	@Override
	public JWTClaimsSet getJWTClaimsSet()
		throws ParseException {

		if (claimsSet != null) {
			return claimsSet;
		}

		Payload payload = getPayload();

		if (payload == null) {
			return null;
		}

		Map<String, Object> json = payload.toJSONObject();

		if (json == null) {
			throw new ParseException("Payload of JWE object is not a valid JSON object", 0);
		}

		claimsSet = JWTClaimsSet.parse(json);
		return claimsSet;
	}

	
	@Override
	protected void setPayload(Payload payload) {

		// setPayload() changes the result of getJWTClaimsSet().
		// set claimsSet = null and reparse payload again when called getJWTClaimsSet().
		claimsSet = null;
		super.setPayload(payload);
	}

	
	/**
	 * Parses an encrypted JSON Web Token (JWT) from the specified string in
	 * compact format. 
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The encrypted JWT.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        encrypted JWT.
	 */
	public static EncryptedJWT parse(final String s)
		throws ParseException {

		Base64URL[] parts = JOSEObject.split(s);

		if (parts.length != 5) {
			throw new ParseException("Unexpected number of Base64URL parts, must be five", 0);
		}

		return new EncryptedJWT(parts[0], parts[1], parts[2], parts[3], parts[4]);
	}
}
