/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2022, Connect2id Ltd.
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

package com.nimbusds.jose.jwk.source;


import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Before;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.proc.SimpleSecurityContext;


public abstract class AbstractWrappedJWKSetSourceTest {

	protected static final String KID = "NkJCQzIyQzRBMEU4NjhGNUU4MzU4RkY0M0ZDQzkwOUQ0Q0VGNUMwQg";

	protected JWKSetSource<SecurityContext> wrappedJWKSetSource;

	protected JWK jwk;

	protected JWKSet jwkSet;

	protected JWKSelector aSelector = new JWKSelector(new JWKMatcher.Builder().keyID("a").build());
	protected JWKSelector bSelector = new JWKSelector(new JWKMatcher.Builder().keyID("b").build());
	protected JWKSelector cSelector = new JWKSelector(new JWKMatcher.Builder().keyID("c").build());
	
	protected SecurityContext context = new SimpleSecurityContext();

	@SuppressWarnings("unchecked")
	@Before
	public void setUp() throws Exception {
		wrappedJWKSetSource = mock(JWKSetSource.class);
		jwk = mock(JWK.class);
		when(jwk.getKeyID()).thenReturn(KID);
		jwkSet = new JWKSet(jwk);

		when(wrappedJWKSetSource.getJWKSet(eq(JWKSetCacheRefreshEvaluator.noRefresh()), anyLong(), any(SecurityContext.class))).thenReturn(jwkSet);
	}
	
	protected JWKSourceBuilder<SecurityContext> builder() {
		return JWKSourceBuilder.create(wrappedJWKSetSource);
	}
	
	protected static SecurityContext anySecurityContext() {
		return any(SecurityContext.class);
	}

	protected static JWKSetCacheRefreshEvaluator anyJWKSetCacheEvaluator() {
		return any(JWKSetCacheRefreshEvaluator.class);
	}
	

	protected static NoRefreshJWKSetCacheEvaluator anyNeverJWKSetCacheEvaluator() {
		return any(NoRefreshJWKSetCacheEvaluator.class);
	}

}
