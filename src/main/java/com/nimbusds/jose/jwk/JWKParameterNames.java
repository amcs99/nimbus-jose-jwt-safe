package com.nimbusds.jose.jwk;


import com.nimbusds.jose.HeaderParameterNames;
import com.nimbusds.jwt.JWTClaimNames;

import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;


/**
 * JSON Web Key (JWK) parameter names. The JWK parameter names defined in
 * <a href="https://datatracker.ietf.org/doc/html/rfc7517">RFC 7517</a> (JWK),
 * <a href="https://datatracker.ietf.org/doc/html/rfc7518">RFC 7518</a> (JWA)
 * and other JOSE related standards are tracked in a
 * <a href="https://www.iana.org/assignments/jose/jose.xhtml#web-key-parameters">JWK
 * parameters registry</a> administered by IANA.
 *
 * @author Nathaniel Hart
 * @version 2024-11-08
 */
public final class JWKParameterNames {
	
	
	////////////////////////////////////////////////////////////////////////////////
	// Generic Key Parameters
	////////////////////////////////////////////////////////////////////////////////
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.1">RFC 7517 "kty" (Key Type) Parameter</a>
	 */
	public static final String KEY_TYPE = "kty";
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.2">RFC 7517 "use" (Public Key Use) Parameter</a>
	 */
	public static final String PUBLIC_KEY_USE = "use";
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.3">RFC 7517 "key_ops" (Key Operations) Parameter</a>
	 */
	public static final String KEY_OPS = "key_ops";
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.4">RFC 7517 "alg" (Algorithm) Parameter</a>
	 */
	public static final String ALGORITHM = HeaderParameterNames.ALGORITHM;
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.5">RFC 7517 "kid" (Key ID) Parameter</a>
	 */
	public static final String KEY_ID = HeaderParameterNames.KEY_ID;
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.6">RFC 7517 "x5u" (X.509 Certificate URL) Parameter</a>
	 */
	public static final String X_509_CERT_URL = HeaderParameterNames.X_509_CERT_URL;
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.7">RFC 7517 "x5c" (X.509 Certificate Chain) Parameter</a>
	 */
	public static final String X_509_CERT_CHAIN = HeaderParameterNames.X_509_CERT_CHAIN;
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.8">RFC 7517 "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter</a>
	 */
	public static final String X_509_CERT_SHA_1_THUMBPRINT = HeaderParameterNames.X_509_CERT_SHA_1_THUMBPRINT;
	
	
	/**
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7517#section-4.9">RFC 7517 "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header
	 * Parameter</a>
	 */
	public static final String X_509_CERT_SHA_256_THUMBPRINT = HeaderParameterNames.X_509_CERT_SHA_256_THUMBPRINT;
	
	
	/**
	 * @see <a href="https://openid.net/specs/openid-federation-1_0.html#name-iana-considerations">OpenID Federation 1.0</a>
	 */
	public static final String EXPIRATION_TIME = JWTClaimNames.EXPIRATION_TIME;
	
	
	/**
	 * @see <a href="https://openid.net/specs/openid-federation-1_0.html#name-iana-considerations">OpenID Federation 1.0</a>
	 */
	public static final String NOT_BEFORE = JWTClaimNames.NOT_BEFORE;
	
	
	/**
	 * @see <a href="https://openid.net/specs/openid-federation-1_0.html#name-iana-considerations">OpenID Federation 1.0</a>
	 */
	public static final String ISSUED_AT = JWTClaimNames.ISSUED_AT;


	/**
	 * @see <a href="https://openid.net/specs/openid-federation-1_0.html#name-iana-considerations">OpenID Federation 1.0</a>
	 */
	public static final String REVOKED = "revoked";
	
	
	////////////////////////////////////////////////////////////////////////////////
	// Algorithm-Specific Key Parameters
	////////////////////////////////////////////////////////////////////////////////
	
	
	// EC
	
	/**
	 * Used with {@link KeyType#EC}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.1">RFC 7518 "crv" (EC Curve) Parameter</a>
	 */
	public static final String ELLIPTIC_CURVE = "crv";
	
	
	/**
	 * Used with {@link KeyType#EC}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.2">RFC 7518 "x" (EC X Coordinate) Parameter</a>
	 */
	public static final String ELLIPTIC_CURVE_X_COORDINATE = "x";
	
	
	/**
	 * Used with {@link KeyType#EC}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.1.3">RFC 7518 "y" (EC Y Coordinate) Parameter</a>
	 */
	public static final String ELLIPTIC_CURVE_Y_COORDINATE = "y";
	
	
	/**
	 * Used with {@link KeyType#EC}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.2.2.1">RFC 7518 "d" (EC Private Key) Parameter</a>
	 */
	public static final String ELLIPTIC_CURVE_PRIVATE_KEY = "d";
	
	
	// RSA
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.1">RFC 7518 "n" (RSA Modulus) Parameter</a>
	 */
	public static final String RSA_MODULUS = "n";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.1.2">RFC 7518 "e" (RSA Exponent) Parameter</a>
	 */
	public static final String RSA_EXPONENT = "e";
	
	
	/**
	 * Used with {@link KeyType#OKP}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.1">RFC 7518 "d" (RSA Private Exponent) Parameter</a>
	 */
	public static final String RSA_PRIVATE_EXPONENT = ELLIPTIC_CURVE_PRIVATE_KEY;
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.2">RFC 7518 "p" (RSA First Prime Factor) Parameter</a>
	 */
	public static final String RSA_FIRST_PRIME_FACTOR = "p";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.3">RFC 7518 "q" (RSA Second Prime Factor) Parameter</a>
	 */
	public static final String RSA_SECOND_PRIME_FACTOR = "q";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.4">RFC 7518 "dp" (RSA First Factor CRT Exponent) Parameter</a>
	 */
	public static final String RSA_FIRST_FACTOR_CRT_EXPONENT = "dp";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.5">RFC 7518 "dq" (RSA Second Factor CRT Exponent) Parameter</a>
	 */
	public static final String RSA_SECOND_FACTOR_CRT_EXPONENT = "dq";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.6">RFC 7518 "qi" (RSA First CRT Coefficient) Parameter</a>
	 */
	public static final String RSA_FIRST_CRT_COEFFICIENT = "qi";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7">RFC 7518 "oth" (RSA Other Primes Info) Parameter</a>
	 */
	public static final String RSA_OTHER_PRIMES = "oth";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7.1">RFC 7518 "r" (RSA Other Primes Info - Prime Factor)</a>
	 */
	public static final String RSA_OTHER_PRIMES__PRIME_FACTOR = "r";
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7.2">RFC 7518 "d" (RSA Other Primes Info - Factor CRT Exponent)</a>
	 */
	public static final String RSA_OTHER_PRIMES__FACTOR_CRT_EXPONENT = ELLIPTIC_CURVE_PRIVATE_KEY;
	
	
	/**
	 * Used with {@link KeyType#RSA}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.3.2.7.3">RFC 7518 "t" (RSA Other Primes Info - Factor CRT Coefficient)</a>
	 */
	public static final String RSA_OTHER_PRIMES__FACTOR_CRT_COEFFICIENT = "t";
	
	
	// OCT
	
	
	/**
	 * Used with {@link KeyType#OCT}
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7518#section-6.4.1">RFC 7518 "k" (OCT Key Value) Parameter</a>
	 */
	public static final String OCT_KEY_VALUE = "k";
	
	
	// OKP
	
	/**
	 * Used with {@link KeyType#OKP}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8037#section-2">RFC 8037 "crv" (OKP Key Subtype) Parameter</a>
	 */
	public static final String OKP_SUBTYPE = ELLIPTIC_CURVE;
	
	
	/**
	 * Used with {@link KeyType#OKP}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8037#section-2">RFC 8037 "x" (OKP Public Key) Parameter</a>
	 */
	public static final String OKP_PUBLIC_KEY = ELLIPTIC_CURVE_X_COORDINATE;
	
	
	/**
	 * Used with {@link KeyType#OKP}.
	 *
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc8037#section-2">RFC 8037 "d" (OKP Private Key) Parameter</a>
	 */
	public static final String OKP_PRIVATE_KEY = ELLIPTIC_CURVE_PRIVATE_KEY;


	/**
	 * The names of public JWK parameters.
	 */
	public static final Set<String> PUBLIC = new HashSet<>(
		Arrays.asList(
			KEY_TYPE,
			PUBLIC_KEY_USE,
			KEY_OPS,
			ALGORITHM,
			KEY_ID,
			X_509_CERT_URL,
			X_509_CERT_CHAIN,
			X_509_CERT_SHA_1_THUMBPRINT,
			X_509_CERT_SHA_256_THUMBPRINT,
			EXPIRATION_TIME,
			NOT_BEFORE,
			ISSUED_AT,
			REVOKED,

			ELLIPTIC_CURVE,
			ELLIPTIC_CURVE_X_COORDINATE,
			ELLIPTIC_CURVE_Y_COORDINATE,

			RSA_MODULUS,
			RSA_EXPONENT,

			OKP_SUBTYPE,
			OKP_PUBLIC_KEY
		)
	);
	
	
	private JWKParameterNames() {}
}
