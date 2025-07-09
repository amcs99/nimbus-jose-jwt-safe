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

package com.nimbusds.jwt.proc;


import java.util.*;

import com.nimbusds.jwt.JWTClaimNames;
import net.jcip.annotations.ThreadSafe;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.util.DateUtils;


/**
 * A {@link JWTClaimsSetVerifier JWT claims verifier} implementation.
 *
 * <p>Configurable checks:
 *
 * <ol>
 *     <li>Specify JWT claims that must be present and which values must match
 *         exactly, for example the expected JWT issuer ("iss") and audience
 *         ("aud").
 *     <li>Specify JWT claims that must be present, for example expiration
 *         ("exp") and not-before ("nbf") times. If the "exp" or "nbf" claims
 *         are marked as required they will be automatically checked against
 *         the current time.
 *     <li>Specify JWT claims that are prohibited, for example to prevent
 *         cross-JWT confusion in situations when explicit JWT typing via the
 *         type ("typ") header is not used.
 * </ol>
 *
 * <p>Performs the following time validity checks:
 *
 * <ol>
 *     <li>If an expiration time ("exp") claim is present, makes sure it is
 *         ahead of the current time, else the JWT claims set is rejected.
 *     <li>If a not-before-time ("nbf") claim is present, makes sure it is
 *         before the current time, else the JWT claims set is rejected.
 * </ol>
 *
 * <p>Note, to enforce a time validity check the claim ("exp" and / or "nbf" )
 * must be set as required.
 *
 * <p>Example verifier with exact matches for "iss" and "aud", and setting the
 * "exp", "nbf" and "jti" claims as required to be present:
 *
 * <pre>
 * DefaultJWTClaimsVerifier&lt;?&gt; verifier = new DefaultJWTClaimsVerifier&lt;&gt;(
 * 	new JWTClaimsSet.Builder()
 * 		.issuer("https://issuer.example.com")
 * 		.audience("https://client.example.com")
 * 		.build(),
 * 	new HashSet&lt;&gt;(Arrays.asList("exp", "nbf", "jti")));
 *
 * verifier.verify(jwtClaimsSet, null);
 * </pre>
 *
 * <p>The {@link #currentTime()} method can be overridden to use an alternative
 * time provider for the "exp" (expiration time) and "nbf" (not-before time)
 * verification, or to disable "exp" and "nbf" verification entirely.
 *
 * <p>This class may be extended to perform additional checks.
 *
 * <p>This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @author Eugene Kuleshov
 * @version 2021-09-28
 */
@ThreadSafe
public class DefaultJWTClaimsVerifier <C extends SecurityContext> implements JWTClaimsSetVerifier<C>, ClockSkewAware {


	/**
	 * The default maximum acceptable clock skew, in seconds (60).
	 */
	public static final int DEFAULT_MAX_CLOCK_SKEW_SECONDS = 60;


	/**
	 * The maximum acceptable clock skew, in seconds.
	 */
	private int maxClockSkew = DEFAULT_MAX_CLOCK_SKEW_SECONDS;
	
	
	/**
	 * The accepted audience values, {@code null} if not specified. A
	 * {@code null} value present in the set allows JWTs with no audience.
	 */
	private final Set<String> acceptedAudienceValues;
	
	
	/**
	 * The JWT claims that must match exactly, empty set if none.
	 */
	private final JWTClaimsSet exactMatchClaims;
	
	
	/**
	 * The names of the JWT claims that must be present, empty set if none.
	 */
	private final Set<String> requiredClaims;
	
	
	/**
	 * The names of the JWT claims that must not be present, empty set if
	 * none.
	 */
	private final Set<String> prohibitedClaims;
	
	
	/**
	 * Creates a new JWT claims verifier. No audience ("aud"), required and
	 * prohibited claims are specified. The expiration ("exp") and
	 * not-before ("nbf") claims will be checked only if they are present
	 * and parsed successfully.
	 *
	 * @deprecated Use a more specific constructor that at least specifies
	 * a list of required JWT claims.
	 */
	@Deprecated
	public DefaultJWTClaimsVerifier() {
		this(null, null, null, null);
	}
	
	
	/**
	 * Creates a new JWT claims verifier. Allows any audience ("aud")
	 * unless an exact match is specified. The expiration ("exp") and
	 * not-before ("nbf") claims will be checked only if they are present
	 * and parsed successfully; add them to the required claims if they are
	 * mandatory.
	 *
	 * @param exactMatchClaims The JWT claims that must match exactly,
	 *                         {@code null} if none.
	 * @param requiredClaims   The names of the JWT claims that must be
	 *                         present, empty set or {@code null} if none.
	 */
	public DefaultJWTClaimsVerifier(final JWTClaimsSet exactMatchClaims,
					final Set<String> requiredClaims) {
		
		this(null, exactMatchClaims, requiredClaims, null);
	}
	
	
	/**
	 * Creates new default JWT claims verifier. The expiration ("exp") and
	 * not-before ("nbf") claims will be checked only if they are present
	 * and parsed successfully; add them to the required claims if they are
	 * mandatory.
	 *
	 * @param requiredAudience The required JWT audience, {@code null} if
	 *                         not specified.
	 * @param exactMatchClaims The JWT claims that must match exactly,
	 *                         {@code null} if none.
	 * @param requiredClaims   The names of the JWT claims that must be
	 *                         present, empty set or {@code null} if none.
	 */
	public DefaultJWTClaimsVerifier(final String requiredAudience,
					final JWTClaimsSet exactMatchClaims,
					final Set<String> requiredClaims) {
		
		this(requiredAudience != null ? Collections.singleton(requiredAudience) : null,
			exactMatchClaims,
			requiredClaims,
			null);
	}
	
	
	/**
	 * Creates new default JWT claims verifier. The expiration ("exp") and
	 * not-before ("nbf") claims will be checked only if they are present
	 * and parsed successfully; add them to the required claims if they are
	 * mandatory.
	 *
	 * @param acceptedAudience The accepted JWT audience values,
	 *                         {@code null} if not specified. A
	 *                         {@code null} value in the set allows JWTs
	 *                         with no audience.
	 * @param exactMatchClaims The JWT claims that must match exactly,
	 *                         {@code null} if none.
	 * @param requiredClaims   The names of the JWT claims that must be
	 *                         present, empty set or {@code null} if none.
	 * @param prohibitedClaims The names of the JWT claims that must not be
	 *                         present, empty set or {@code null} if none.
	 */
	public DefaultJWTClaimsVerifier(final Set<String> acceptedAudience,
					final JWTClaimsSet exactMatchClaims,
					final Set<String> requiredClaims,
					final Set<String> prohibitedClaims) {
		
		this.acceptedAudienceValues = acceptedAudience != null ? Collections.unmodifiableSet(acceptedAudience) : null;
		
		this.exactMatchClaims = exactMatchClaims != null ? exactMatchClaims : new JWTClaimsSet.Builder().build();
		
		Set<String> requiredClaimsCopy = new HashSet<>(this.exactMatchClaims.getClaims().keySet());
		if (acceptedAudienceValues != null && ! acceptedAudienceValues.contains(null)) {
			// check if an explicit aud is required
			requiredClaimsCopy.add(JWTClaimNames.AUDIENCE);
		}
		if (requiredClaims != null) {
			requiredClaimsCopy.addAll(requiredClaims);
		}
		this.requiredClaims = Collections.unmodifiableSet(requiredClaimsCopy);
		
		this.prohibitedClaims = prohibitedClaims != null ? Collections.unmodifiableSet(prohibitedClaims) : Collections.<String>emptySet();
	}
	
	
	/**
	 * Returns the accepted audience values.
	 *
	 * @return The accepted JWT audience values, {@code null} if not
	 *         specified. A {@code null} value in the set allows JWTs with
	 *         no audience.
	 */
	public Set<String> getAcceptedAudienceValues() {
		return acceptedAudienceValues;
	}
	
	
	/**
	 * Returns the JWT claims that must match exactly.
	 *
	 * @return The JWT claims that must match exactly, empty set if none.
	 */
	public JWTClaimsSet getExactMatchClaims() {
		return exactMatchClaims;
	}
	
	
	/**
	 * Returns the names of the JWT claims that must be present, including
	 * the name of those that must match exactly.
	 *
	 * @return The names of the JWT claims that must be present, empty set
	 *         if none.
	 */
	public Set<String> getRequiredClaims() {
		return requiredClaims;
	}
	
	
	/**
	 * Returns the names of the JWT claims that must not be present.
	 *
	 * @return The names of the JWT claims that must not be present, empty
	 *         set if none.
	 */
	public Set<String> getProhibitedClaims() {
		return prohibitedClaims;
	}
	
	
	@Override
	public int getMaxClockSkew() {
		return maxClockSkew;
	}


	@Override
	public void setMaxClockSkew(final int maxClockSkewSeconds) {
		maxClockSkew = maxClockSkewSeconds;
	}
	
	
	@Override
	public void verify(final JWTClaimsSet claimsSet, final C context)
		throws BadJWTException {
		
		// Check audience
		if (acceptedAudienceValues != null) {
			List<String> audList = claimsSet.getAudience();
			if (audList != null && ! audList.isEmpty()) {
				boolean audMatch = false;
				for (String aud : audList) {
					if (acceptedAudienceValues.contains(aud)) {
						audMatch = true;
						break;
					}
				}
				if (! audMatch) {
					throw new BadJWTException("JWT audience rejected: " + audList);
				}
			} else if (! acceptedAudienceValues.contains(null)) {
				throw new BadJWTException("JWT missing required audience");
			}
		}
		
		// Check if all required claims are present
		if (! claimsSet.getClaims().keySet().containsAll(requiredClaims)) {
			SortedSet<String> missingClaims = new TreeSet<>(requiredClaims);
			missingClaims.removeAll(claimsSet.getClaims().keySet());
			throw new BadJWTException("JWT missing required claims: " + missingClaims);
		}
		
		// Check if prohibited claims are present
		SortedSet<String> presentProhibitedClaims = new TreeSet<>();
		for (String prohibited: prohibitedClaims) {
			if (claimsSet.getClaims().containsKey(prohibited)) {
				presentProhibitedClaims.add(prohibited);
			}
		}
		if (! presentProhibitedClaims.isEmpty()) {
			throw new BadJWTException("JWT has prohibited claims: " + presentProhibitedClaims);
		}
		
		// Check exact matches
		for (String exactMatch: exactMatchClaims.getClaims().keySet()) {
			Object actualClaim = claimsSet.getClaim(exactMatch);
			Object expectedClaim = exactMatchClaims.getClaim(exactMatch);
			if (! Objects.equals(expectedClaim, actualClaim)) {
				throw new BadJWTException("JWT " + exactMatch + " claim has value " + actualClaim + ", must be " + expectedClaim);
			}
		}
		
		// Check time window
		final Date now = currentTime();

		if (now != null) {
			final Date exp = claimsSet.getExpirationTime();
			if (exp != null) {

				if (! DateUtils.isAfter(exp, now, maxClockSkew)) {
					throw new ExpiredJWTException("Expired JWT");
				}
			}

			final Date nbf = claimsSet.getNotBeforeTime();
			if (nbf != null) {

				if (! DateUtils.isBefore(nbf, now, maxClockSkew)) {
					throw new BadJWTException("JWT before use time");
				}
			}
		}
	}

	
	/**
	 * Returns the current time for the purpose of "exp" (expiration time)
	 * and "nbf" (not-before time) claim verification. This method can be
	 * overridden to inject an alternative time provider (e.g. for testing
	 * purposes) or to disable "exp" and "nbf" verification.
	 *
	 * @return The current time or {@code null} to disable "exp" and "nbf"
	 *         claim verification entirely.
	 */
	protected Date currentTime() {
		
		return new Date();
	}
}
