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


import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.JSONArrayUtils;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.util.DateUtils;
import net.jcip.annotations.Immutable;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.*;


/**
 * JSON Web Token (JWT) claims set. This class is immutable.
 *
 * <p>Supports all {@link #getRegisteredNames() registered claims} of the JWT
 * specification:
 *
 * <ul>
 *     <li>iss - Issuer
 *     <li>sub - Subject
 *     <li>aud - Audience
 *     <li>exp - Expiration Time
 *     <li>nbf - Not Before
 *     <li>iat - Issued At
 *     <li>jti - JWT ID
 * </ul>
 *
 * <p>The set may also contain custom claims.
 *
 * <p>Claims with {@code null} values will not be serialised with
 * {@link #toPayload()} / {@link #toJSONObject()} / {@link #toString()} unless
 * {@link Builder#serializeNullClaims} is enabled.
 *
 * <p>Example JWT claims set:
 *
 * <pre>
 * {
 *   "sub"                         : "joe",
 *   "exp"                         : 1300819380,
 *   "https://example.com/is_root" : true
 * }
 * </pre>
 *
 * <p>Example usage:
 *
 * <pre>
 * JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
 *     .subject("joe")
 *     .expirationTime(new Date(1300819380 * 1000l)
 *     .claim("http://example.com/is_root", true)
 *     .build();
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @author Joey Zhao
 * @version 2024-12-20
 */
@Immutable
public final class JWTClaimsSet implements Serializable {


	private static final long serialVersionUID = 1L;


	/**
	 * The registered claim names.
	 */
	private static final Set<String> REGISTERED_CLAIM_NAMES;


	/*
	 * Initialises the registered claim name set.
	 */
	static {
		Set<String> n = new HashSet<>();

		n.add(JWTClaimNames.ISSUER);
		n.add(JWTClaimNames.SUBJECT);
		n.add(JWTClaimNames.AUDIENCE);
		n.add(JWTClaimNames.EXPIRATION_TIME);
		n.add(JWTClaimNames.NOT_BEFORE);
		n.add(JWTClaimNames.ISSUED_AT);
		n.add(JWTClaimNames.JWT_ID);

		REGISTERED_CLAIM_NAMES = Collections.unmodifiableSet(n);
	}


	/**
	 * Builder for constructing JSON Web Token (JWT) claims sets.
	 *
	 * <p>Example usage:
	 *
	 * <pre>
	 * JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
	 *     .subject("joe")
	 *     .expirationDate(new Date(1300819380 * 1000l)
	 *     .claim("http://example.com/is_root", true)
	 *     .build();
	 * </pre>
	 */
	public static class Builder {


		/**
		 * The claims.
		 */
		private final Map<String,Object> claims = new LinkedHashMap<>();


		/**
		 * Controls serialisation of claims with {@code null} values.
		 */
		private boolean serializeNullClaims = false;


		/**
		 * Creates a new builder.
		 */
		public Builder() {

			// Nothing to do
		}


		/**
		 * Creates a new builder with the claims from the specified
		 * set.
		 *
		 * @param jwtClaimsSet The JWT claims set to use. Must not be
		 *                     {@code null}.
		 */
		public Builder(final JWTClaimsSet jwtClaimsSet) {

			claims.putAll(jwtClaimsSet.claims);
		}


		/**
		 * Controls the serialisation of claims with {@code null}
		 * values when {@link #toPayload()} / {@link #toJSONObject()} /
		 * {@link #toString()} is called. Disabled by default.
		 *
		 * @param enable {@code true} to serialise claims with
		 *               {@code null} values, {@code false} to omit
		 *               them.
		 *
		 * @return This builder.
		 */
		public Builder serializeNullClaims(final boolean enable) {

			serializeNullClaims = enable;
			return this;
		}


		/**
		 * Sets the issuer ({@code iss}) claim.
		 *
		 * @param iss The issuer claim, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder issuer(final String iss) {

			claims.put(JWTClaimNames.ISSUER, iss);
			return this;
		}


		/**
		 * Sets the subject ({@code sub}) claim.
		 *
		 * @param sub The subject claim, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder subject(final String sub) {

			claims.put(JWTClaimNames.SUBJECT, sub);
			return this;
		}


		/**
		 * Sets the audience ({@code aud}) claim.
		 *
		 * @param aud The audience claim, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder audience(final List<String> aud) {

			claims.put(JWTClaimNames.AUDIENCE, aud);
			return this;
		}


		/**
		 * Sets a single-valued audience ({@code aud}) claim.
		 *
		 * @param aud The audience claim, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder audience(final String aud) {

			if (aud == null) {
				claims.put(JWTClaimNames.AUDIENCE, null);
			} else {
				claims.put(JWTClaimNames.AUDIENCE, Collections.singletonList(aud));
			}
			return this;
		}


		/**
		 * Sets the expiration time ({@code exp}) claim.
		 *
		 * @param exp The expiration time, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder expirationTime(final Date exp) {

			claims.put(JWTClaimNames.EXPIRATION_TIME, exp);
			return this;
		}


		/**
		 * Sets the not-before ({@code nbf}) claim.
		 *
		 * @param nbf The not-before claim, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder notBeforeTime(final Date nbf) {

			claims.put(JWTClaimNames.NOT_BEFORE, nbf);
			return this;
		}


		/**
		 * Sets the issued-at ({@code iat}) claim.
		 *
		 * @param iat The issued-at claim, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		public Builder issueTime(final Date iat) {

			claims.put(JWTClaimNames.ISSUED_AT, iat);
			return this;
		}


		/**
		 * Sets the JWT ID ({@code jti}) claim.
		 *
		 * @param jti The JWT ID claim, {@code null} if not specified.
		 *
		 * @return This builder.
		 */
		public Builder jwtID(final String jti) {

			claims.put(JWTClaimNames.JWT_ID, jti);
			return this;
		}


		/**
		 * Sets the specified claim (registered or custom).
		 *
		 * @param name  The name of the claim to set. Must not be
		 *              {@code null}.
		 * @param value The value of the claim to set, {@code null} if
		 *              not specified. Should map to a JSON entity.
		 *
		 * @return This builder.
		 */
		public Builder claim(final String name, final Object value) {

			claims.put(name, value);
			return this;
		}
		
		
		/**
		 * Gets the claims (registered and custom).
		 *
		 * <p>Note that the registered claims Expiration-Time
		 * ({@code exp}), Not-Before-Time ({@code nbf}) and Issued-At
		 * ({@code iat}) will be returned as {@code java.util.Date}
		 * instances.
		 *
		 * @return The claims, as an unmodifiable map, empty map if
		 *         none.
		 */
		public Map<String,Object> getClaims() {
			
			return Collections.unmodifiableMap(claims);
		}


		/**
		 * Builds a new JWT claims set.
		 *
		 * @return The JWT claims set.
		 */
		public JWTClaimsSet build() {

			return new JWTClaimsSet(claims, serializeNullClaims);
		}
	}


	/**
	 * The claims map.
	 */
	private final Map<String,Object> claims = new LinkedHashMap<>();


	/**
	 * Controls serialisation of claims with {@code null} values.
	 */
	private final boolean serializeNullClaims;


	/**
	 * Creates a new JWT claims set.
	 *
	 * @param claims The JWT claims set as a map. Must not be {@code null}.
	 */
	private JWTClaimsSet(final Map<String,Object> claims,
			     final boolean serializeNullClaims) {
		
		this.claims.putAll(claims);
		this.serializeNullClaims = serializeNullClaims;
	}


	/**
	 * Gets the registered JWT claim names.
	 *
	 * @return The registered claim names, as an unmodifiable set.
	 */
	public static Set<String> getRegisteredNames() {

		return REGISTERED_CLAIM_NAMES;
	}


	/**
	 * Gets the issuer ({@code iss}) claim.
	 *
	 * @return The issuer claim, {@code null} if not specified.
	 */
	public String getIssuer() {

		try {
			return getStringClaim(JWTClaimNames.ISSUER);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets the subject ({@code sub}) claim.
	 *
	 * @return The subject claim, {@code null} if not specified.
	 */
	public String getSubject() {

		try {
			return getStringClaim(JWTClaimNames.SUBJECT);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets the audience ({@code aud}) claim.
	 *
	 * @return The audience claim, empty list if not specified.
	 */
	public List<String> getAudience() {

		Object audValue = getClaim(JWTClaimNames.AUDIENCE);
		
		if (audValue instanceof String) {
			// Special case
			return Collections.singletonList((String)audValue);
		}
		
		List<String> aud;
		try {
			aud = getStringListClaim(JWTClaimNames.AUDIENCE);
		} catch (ParseException e) {
			return Collections.emptyList();
		}
		return aud != null ? aud : Collections.<String>emptyList();
	}


	/**
	 * Gets the expiration time ({@code exp}) claim.
	 *
	 * @return The expiration time, {@code null} if not specified.
	 */
	public Date getExpirationTime() {

		try {
			return getDateClaim(JWTClaimNames.EXPIRATION_TIME);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets the not-before ({@code nbf}) claim.
	 *
	 * @return The not-before claim, {@code null} if not specified.
	 */
	public Date getNotBeforeTime() {

		try {
			return getDateClaim(JWTClaimNames.NOT_BEFORE);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets the issued-at ({@code iat}) claim.
	 *
	 * @return The issued-at claim, {@code null} if not specified.
	 */
	public Date getIssueTime() {

		try {
			return getDateClaim(JWTClaimNames.ISSUED_AT);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets the JWT ID ({@code jti}) claim.
	 *
	 * @return The JWT ID claim, {@code null} if not specified.
	 */
	public String getJWTID() {

		try {
			return getStringClaim(JWTClaimNames.JWT_ID);
		} catch (ParseException e) {
			return null;
		}
	}


	/**
	 * Gets the specified claim (registered or custom).
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 */
	public Object getClaim(final String name) {

		return claims.get(name);
	}


	/**
	 * Gets the specified claim (registered or custom) as
	 * {@link java.lang.String}.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	public String getStringClaim(final String name)
		throws ParseException {
		
		Object value = getClaim(name);
		
		if (value == null || value instanceof String) {
			return (String)value;
		} else {
			throw new ParseException("The " + name + " claim is not a String", 0);
		}
	}

	/**
     * Gets the specified claim (registered or custom) as
     * {@link java.lang.String}, primitive or Wrapper types will be converted to
     * {@link java.lang.String}.
     *
     *
     * @param name The name of the claim. Must not be {@code null}.
     *
     * @return The value of the claim, {@code null} if not specified.
     *
     * @throws ParseException If the claim value is not and cannot be
     *                        automatically converted to {@link java.lang.String}.
     */
    public String getClaimAsString(final String name)
            throws ParseException {

        Object value = getClaim(name);

        Class<?> clazz;
        if (value == null || value instanceof String) {
            return (String) value;
        } else if ((clazz = value.getClass()).isPrimitive() || isWrapper(clazz)) {
            return String.valueOf(value);
        } else {
            throw new ParseException("The " + name + " claim is not and cannot be converted to a String", 0);
        }
    }


    /**
     * Checks if a class is a Java Wrapper class.
     *
     * @param clazz The class to check against.
     *
     * @return {@code true} if the class is a Wrapper class, otherwise
     * {@code false}.
     */
    private static boolean isWrapper(Class<?> clazz) {
        return clazz == Integer.class || clazz == Double.class || clazz == Float.class
                || clazz == Long.class || clazz == Short.class || clazz == Byte.class
                || clazz == Character.class || clazz == Boolean.class;
    }


	/**
	 * Gets the specified claims (registered or custom) as a
	 * {@link java.util.List} list of objects.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	public List<Object> getListClaim(final String name)
		throws ParseException {

		Object value = getClaim(name);

		if (value == null) {
			return null;
		}

		try {
			return (List<Object>)getClaim(name);

		} catch (ClassCastException e) {
			throw new ParseException("The " + name + " claim is not a list / JSON array", 0);
		}
	}


	/**
	 * Gets the specified claims (registered or custom) as a
	 * {@link java.lang.String} array.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	public String[] getStringArrayClaim(final String name)
		throws ParseException {

		List<?> list = getListClaim(name);

		if (list == null) {
			return null;
		}

		String[] stringArray = new String[list.size()];

		for (int i=0; i < stringArray.length; i++) {

			try {
				stringArray[i] = (String)list.get(i);
			} catch (ClassCastException e) {
				throw new ParseException("The " + name + " claim is not a list / JSON array of strings", 0);
			}
		}

		return stringArray;
	}


	/**
	 * Gets the specified claims (registered or custom) as a
	 * {@link java.util.List} list of strings.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	public List<String> getStringListClaim(final String name)
		throws ParseException {

		String[] stringArray = getStringArrayClaim(name);

		if (stringArray == null) {
			return null;
		}

		return Collections.unmodifiableList(Arrays.asList(stringArray));
	}
	
	
	/**
	 * Gets the specified claim (registered or custom) as a
	 * {@link java.net.URI}.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim couldn't be parsed to a URI.
	 */
	public URI getURIClaim(final String name)
		throws ParseException {
		
		String uriString = getStringClaim(name);
		
		if (uriString == null) {
			return null;
		}
		
		try {
			return new URI(uriString);
		} catch (URISyntaxException e) {
			throw new ParseException("The \"" + name + "\" claim is not a URI: " + e.getMessage(), 0);
		}
	}


	/**
	 * Gets the specified claim (registered or custom) as
	 * {@link java.lang.Boolean}.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	public Boolean getBooleanClaim(final String name)
		throws ParseException {
		
		Object value = getClaim(name);
		
		if (value == null || value instanceof Boolean) {
			return (Boolean)value;
		} else {
			throw new ParseException("The \"" + name + "\" claim is not a Boolean", 0);
		}
	}


	/**
	 * Gets the specified claim (registered or custom) as
	 * {@link java.lang.Integer}.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	public Integer getIntegerClaim(final String name)
		throws ParseException {
		
		Object value = getClaim(name);
		
		if (value == null) {
			return null;
		} else if (value instanceof Number) {
			return ((Number)value).intValue();
		} else {
			throw new ParseException("The \"" + name + "\" claim is not an Integer", 0);
		}
	}


	/**
	 * Gets the specified claim (registered or custom) as
	 * {@link java.lang.Long}.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	public Long getLongClaim(final String name)
		throws ParseException {
		
		Object value = getClaim(name);
		
		if (value == null) {
			return null;
		} else if (value instanceof Number) {
			return ((Number)value).longValue();
		} else {
			throw new ParseException("The \"" + name + "\" claim is not a Number", 0);
		}
	}


	/**
	 * Gets the specified claim (registered or custom) as
	 * {@link java.util.Date}. The claim may be represented by a Date
	 * object or a number of a seconds since the Unix epoch.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	public Date getDateClaim(final String name)
		throws ParseException {

		Object value = getClaim(name);

		if (value == null) {
			return null;
		} else if (value instanceof Date) {
			return (Date)value;
		} else if (value instanceof Number) {
			return DateUtils.fromSecondsSinceEpoch(((Number)value).longValue());
		} else {
			throw new ParseException("The \"" + name + "\" claim is not a Date", 0);
		}
	}


	/**
	 * Gets the specified claim (registered or custom) as
	 * {@link java.lang.Float}.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	public Float getFloatClaim(final String name)
		throws ParseException {
		
		Object value = getClaim(name);
		
		if (value == null) {
			return null;
		} else if (value instanceof Number) {
			return ((Number)value).floatValue();
		} else {
			throw new ParseException("The \"" + name + "\" claim is not a Float", 0);
		}
	}


	/**
	 * Gets the specified claim (registered or custom) as
	 * {@link java.lang.Double}.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	public Double getDoubleClaim(final String name)
		throws ParseException {
		
		Object value = getClaim(name);
		
		if (value == null) {
			return null;
		} else if (value instanceof Number) {
			return ((Number)value).doubleValue();
		} else {
			throw new ParseException("The \"" + name + "\" claim is not a Double", 0);
		}
	}


	/**
	 * Gets the specified claim (registered or custom) as a JSON object.
	 *
	 * @param name The name of the claim. Must not be {@code null}.
	 *
	 * @return The value of the claim, {@code null} if not specified.
	 *
	 * @throws ParseException If the claim value is not of the required
	 *                        type.
	 */
	public Map<String, Object> getJSONObjectClaim(final String name)
		throws ParseException {

		Object value = getClaim(name);

		if (value == null) {
			return null;
		} else if (value instanceof Map) {
			Map<String, Object> jsonObject = JSONObjectUtils.newJSONObject();
			Map<?,?> map = (Map<?,?>)value;
			for (Map.Entry<?,?> entry: map.entrySet()) {
				if (entry.getKey() instanceof String) {
					jsonObject.put((String)entry.getKey(), entry.getValue());
				}
			}
			return jsonObject;
		} else {
			throw new ParseException("The \"" + name + "\" claim is not a JSON object or Map", 0);
		}
	}


	/**
	 * Gets the claims (registered and custom).
	 *
	 * <p>Note that the registered claims Expiration-Time ({@code exp}),
	 * Not-Before-Time ({@code nbf}) and Issued-At ({@code iat}) will be
	 * returned as {@code java.util.Date} instances.
	 *
	 * @return The claims, as an unmodifiable map, empty map if none.
	 */
	public Map<String,Object> getClaims() {

		return Collections.unmodifiableMap(claims);
	}
	
	
	/**
	 * Returns a JOSE object payload representation of this claims set. The
	 * claims are serialised according to their insertion order. Claims
	 * with {@code null} values are output according to
	 * {@link Builder#serializeNullClaims(boolean)}.
	 *
	 * @return The payload representation.
	 */
	public Payload toPayload() {
		
		return new Payload(toJSONObject(serializeNullClaims));
	}


	/**
	 * Returns a JOSE object payload representation of this claims set. The
	 * claims are serialised according to their insertion order.
	 *
	 * @param serializeNullClaims {@code true} to serialise claims with
	 *                            {@code null} values, {@code false} to
	 *                            omit them.
	 *
	 * @return The payload representation.
	 */
	public Payload toPayload(final boolean serializeNullClaims) {

		return new Payload(toJSONObject(serializeNullClaims));
	}


	/**
	 * Returns the JSON object representation of this claims set. The
	 * claims are serialised according to their insertion order. Claims
	 * with {@code null} values are output according to
	 * {@link Builder#serializeNullClaims(boolean)}.
	 *
	 * @return The JSON object representation.
	 */
	public Map<String, Object> toJSONObject() {

		return toJSONObject(serializeNullClaims);
	}
	
	
	/**
	 * Returns the JSON object representation of this claims set. The
	 * claims are serialised according to their insertion order.
	 *
	 * @param serializeNullClaims {@code true} to serialise claims with
	 *                            {@code null} values, {@code false} to
	 *                            omit them.
	 *
	 * @return The JSON object representation.
	 */
	public Map<String, Object> toJSONObject(final boolean serializeNullClaims) {
		
		Map<String, Object> o = JSONObjectUtils.newJSONObject();
		
		for (Map.Entry<String,Object> claim: claims.entrySet()) {
			
			if (claim.getValue() instanceof Date) {
				
				// Transform dates to Unix timestamps
				Date dateValue = (Date) claim.getValue();
				o.put(claim.getKey(), DateUtils.toSecondsSinceEpoch(dateValue));
				
			} else if (JWTClaimNames.AUDIENCE.equals(claim.getKey())) {
				
				// Serialise single audience list and string
				List<String> audList = getAudience();
				
				if (audList != null && ! audList.isEmpty()) {
					if (audList.size() == 1) {
						o.put(JWTClaimNames.AUDIENCE, audList.get(0));
					} else {
						List<Object> audArray = JSONArrayUtils.newJSONArray();
						audArray.addAll(audList);
						o.put(JWTClaimNames.AUDIENCE, audArray);
					}
				} else if (serializeNullClaims) {
					o.put(JWTClaimNames.AUDIENCE, null);
				}
				
			} else if (claim.getValue() != null) {
				o.put(claim.getKey(), claim.getValue());
			} else if (serializeNullClaims) {
				o.put(claim.getKey(), null);
			}
		}
		
		return o;
	}
	
	
	/**
	 * Returns a JSON object string representation of this claims set. The
	 * claims are serialised according to their insertion order. Claims
	 * with {@code null} values are output according to
	 * {@link Builder#serializeNullClaims(boolean)}.
	 *
	 * @return The JSON object string representation.
	 */
	@Override
	public String toString() {

		return JSONObjectUtils.toJSONString(toJSONObject());
	}
	
	
	/**
	 * Returns a JSON object string representation of this claims set. The
	 * claims are serialised according to their insertion order.
	 *
	 * @param serializeNullClaims {@code true} to serialise claims with
	 *                            {@code null} values, {@code false} to
	 *                            omit them.
	 *
	 * @return The JSON object string representation.
	 */
	public String toString(final boolean serializeNullClaims) {

		return JSONObjectUtils.toJSONString(toJSONObject(serializeNullClaims));
	}

	
	/**
	 * Returns a transformation of this JWT claims set.
	 *
	 * @param <T> Type of the result.
	 * @param transformer The JWT claims set transformer. Must not be
	 *                    {@code null}.
	 *
	 * @return The transformed JWT claims set.
	 */
	public <T> T toType(final JWTClaimsSetTransformer<T> transformer) {

		return transformer.transform(this);
	}


	/**
	 * Parses a JSON Web Token (JWT) claims set from the specified JSON
	 * object representation.
	 *
	 * @param json The JSON object to parse. Must not be {@code null}.
	 *
	 * @return The JWT claims set.
	 *
	 * @throws ParseException If the specified JSON object doesn't 
	 *                        represent a valid JWT claims set.
	 */
	public static JWTClaimsSet parse(final Map<String, Object> json)
		throws ParseException {

		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		// Parse registered + custom params
		for (final String name: json.keySet()) {
			
			switch (name) {
				case JWTClaimNames.ISSUER:
					builder.issuer(JSONObjectUtils.getString(json, JWTClaimNames.ISSUER));
					break;
				case JWTClaimNames.SUBJECT:
					Object subValue = json.get(JWTClaimNames.SUBJECT);
					if (subValue instanceof String) {
						builder.subject(JSONObjectUtils.getString(json, JWTClaimNames.SUBJECT));
					} else if (subValue instanceof Number) {
						// Numbers not allowed per JWT spec, compromise
						// to enable interop with non-compliant libs
						// https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2
						builder.subject(String.valueOf(subValue));
					} else if (subValue == null) {
						builder.subject(null);
					} else {
						throw new ParseException("Illegal " + JWTClaimNames.SUBJECT + " claim", 0);
					}
					break;
				case JWTClaimNames.AUDIENCE:
					Object audValue = json.get(JWTClaimNames.AUDIENCE);
					if (audValue instanceof String) {
						List<String> singleAud = new ArrayList<>();
						singleAud.add(JSONObjectUtils.getString(json, JWTClaimNames.AUDIENCE));
						builder.audience(singleAud);
					} else if (audValue instanceof List) {
						builder.audience(JSONObjectUtils.getStringList(json, JWTClaimNames.AUDIENCE));
					} else if (audValue == null) {
						builder.audience((String) null);
					} else {
						throw new ParseException("Illegal " + JWTClaimNames.AUDIENCE + " claim", 0);
					}
					break;
				case JWTClaimNames.EXPIRATION_TIME:
					builder.expirationTime(JSONObjectUtils.getEpochSecondAsDate(json, JWTClaimNames.EXPIRATION_TIME));
					break;
				case JWTClaimNames.NOT_BEFORE:
					builder.notBeforeTime(JSONObjectUtils.getEpochSecondAsDate(json, JWTClaimNames.NOT_BEFORE));
					break;
				case JWTClaimNames.ISSUED_AT:
					builder.issueTime(JSONObjectUtils.getEpochSecondAsDate(json, JWTClaimNames.ISSUED_AT));
					break;
				case JWTClaimNames.JWT_ID:
					builder.jwtID(JSONObjectUtils.getString(json, JWTClaimNames.JWT_ID));
					break;
				default:
					builder.claim(name, json.get(name));
					break;
			}
		}

		return builder.build();
	}


	/**
	 * Parses a JSON Web Token (JWT) claims set from the specified JSON
	 * object string representation.
	 *
	 * @param s The JSON object string to parse. Must not be {@code null}.
	 *
	 * @return The JWT claims set.
	 *
	 * @throws ParseException If the specified JSON object string doesn't
	 *                        represent a valid JWT claims set.
	 */
	public static JWTClaimsSet parse(final String s)
		throws ParseException {

		return parse(JSONObjectUtils.parse(s));
	}

	
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (!(o instanceof JWTClaimsSet)) return false;
		JWTClaimsSet that = (JWTClaimsSet) o;
		return Objects.equals(claims, that.claims);
	}

	
	@Override
	public int hashCode() {
		return Objects.hash(claims);
	}
}
