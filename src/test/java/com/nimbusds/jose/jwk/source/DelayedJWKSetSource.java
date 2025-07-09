/*
 * nimbus-jose-jwt
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
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


import java.io.IOException;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.proc.SecurityContext;


/**
 * Test helper class simulating a network delay when getting a JWKSet.
 */
public class DelayedJWKSetSource<C extends SecurityContext> extends MutableJWKSetSource<C> {
	
	private final long delay;
	
	public DelayedJWKSetSource(long delay) {
		this.delay = delay;
		
	}
	
	@Override
	public void close() throws IOException {
		// do nothing
	}
	
	@Override
	public JWKSet getJWKSet(JWKSetCacheRefreshEvaluator refreshEvaluator, long currentTime, C context)
		throws KeySourceException {
		
		try {
			Thread.sleep(delay);
			return super.getJWKSet(refreshEvaluator, currentTime, context);
		} catch (InterruptedException e) {
			Thread.interrupted();
			throw new KeySourceException(e);
		}
	}
}