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

package com.nimbusds.jose.jwk;


import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jose.util.X509CertChainUtils;
import com.nimbusds.jwt.util.DateUtils;

import java.net.URI;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;


/**
 * JSON Web Key (JWK) metadata.
 *
 * @author Vladimir Dzhuvinov
 * @version 2024-04-27
 */
final class JWKMetadata {


	/**
	 * Parses the JWK type.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key type.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static KeyType parseKeyType(final Map<String, Object> o)
		throws ParseException {

		try {
			return KeyType.parse(JSONObjectUtils.getString(o, JWKParameterNames.KEY_TYPE));
		} catch (IllegalArgumentException e) {
			throw new ParseException(e.getMessage(), 0);
		}
	}


	/**
	 * Parses the optional public key use.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key use, {@code null} if not specified or if the key is
	 *         intended for signing as well as encryption.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static KeyUse parseKeyUse(final Map<String, Object> o)
		throws ParseException {

		return KeyUse.parse(JSONObjectUtils.getString(o, JWKParameterNames.PUBLIC_KEY_USE));
	}


	/**
	 * Parses the optional key operations.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key operations, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static Set<KeyOperation> parseKeyOperations(final Map<String, Object> o)
		throws ParseException {
		
		return KeyOperation.parse(JSONObjectUtils.getStringList(o, JWKParameterNames.KEY_OPS));
	}


	/**
	 * Parses the optional algorithm.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return  The intended JOSE algorithm, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static Algorithm parseAlgorithm(final Map<String, Object> o)
		throws ParseException {

		return Algorithm.parse(JSONObjectUtils.getString(o, JWKParameterNames.ALGORITHM));
	}


	/**
	 * Parses the optional key ID.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key ID, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static String parseKeyID(final Map<String, Object> o)
		throws ParseException {

		return JSONObjectUtils.getString(o, JWKParameterNames.KEY_ID);
	}


	/**
	 * Parses the optional X.509 certificate URL.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The X.509 certificate URL, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static URI parseX509CertURL(final Map<String, Object> o)
		throws ParseException {

		return JSONObjectUtils.getURI(o, JWKParameterNames.X_509_CERT_URL);
	}


	/**
	 * Parses the optional X.509 certificate thumbprint.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The X.509 certificate thumbprint, {@code null} if not
	 *         specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static Base64URL parseX509CertThumbprint(final Map<String, Object> o)
		throws ParseException {

		return JSONObjectUtils.getBase64URL(o, JWKParameterNames.X_509_CERT_SHA_1_THUMBPRINT);
	}


	/**
	 * Parses the optional X.509 certificate SHA-256 thumbprint.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The X.509 certificate SHA-256 thumbprint, {@code null} if
	 *         not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static Base64URL parseX509CertSHA256Thumbprint(final Map<String, Object> o)
		throws ParseException {

		return JSONObjectUtils.getBase64URL(o, JWKParameterNames.X_509_CERT_SHA_256_THUMBPRINT);
	}


	/**
	 * Parses the optional X.509 certificate chain.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The X.509 certificate chain (containing at least one
	 *         certificate) as an unmodifiable list, {@code null} if not
	 *         specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static List<Base64> parseX509CertChain(final Map<String, Object> o)
		throws ParseException {
		
		// https://tools.ietf.org/html/rfc7517#section-4.7
		List<Base64> chain = X509CertChainUtils.toBase64List(JSONObjectUtils.getJSONArray(o, JWKParameterNames.X_509_CERT_CHAIN));
		
		if (chain == null || ! chain.isEmpty()) {
			return chain;
		}
		
		return null; // Empty chains not allowed
	}
	
	
	/**
	 * Parses the optional expiration time.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The expiration time, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static Date parseExpirationTime(final Map<String, Object> o)
		throws ParseException {
		
		if (o.get(JWKParameterNames.EXPIRATION_TIME) == null) {
			return null;
		}
		
		return DateUtils.fromSecondsSinceEpoch(JSONObjectUtils.getLong(o, JWKParameterNames.EXPIRATION_TIME));
	}
	
	
	/**
	 * Parses the optional not-before time.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The not-before time, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static Date parseNotBeforeTime(final Map<String, Object> o)
		throws ParseException {
		
		if (o.get(JWKParameterNames.NOT_BEFORE) == null) {
			return null;
		}
		
		return DateUtils.fromSecondsSinceEpoch(JSONObjectUtils.getLong(o, JWKParameterNames.NOT_BEFORE));
	}
	
	
	/**
	 * Parses the optional issued-at time.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The issued-at time, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static Date parseIssueTime(final Map<String, Object> o)
		throws ParseException {
		
		if (o.get(JWKParameterNames.ISSUED_AT) == null) {
			return null;
		}
		
		return DateUtils.fromSecondsSinceEpoch(JSONObjectUtils.getLong(o, JWKParameterNames.ISSUED_AT));
	}


	/**
	 * Parses the optional key revocation.
	 *
	 * @param o The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The key revocation, {@code null} if not specified.
	 *
	 * @throws ParseException If parsing failed.
	 */
	static KeyRevocation parseKeyRevocation(final Map<String, Object> o)
		throws ParseException {

		if (o.get(JWKParameterNames.REVOKED) == null) {
			return null;
		}

		return KeyRevocation.parse(JSONObjectUtils.getJSONObject(o, JWKParameterNames.REVOKED));
	}
}
