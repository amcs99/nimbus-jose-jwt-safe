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


import com.nimbusds.jose.util.JSONStringUtils;
import net.jcip.annotations.Immutable;

import java.io.Serializable;
import java.util.Objects;


/**
 * The base class for algorithm names, with optional implementation 
 * requirement. This class is immutable.
 *
 * <p>Includes constants for the following standard algorithm names:
 *
 * <ul>
 *     <li>{@link #NONE none}
 * </ul>
 *
 * @author Vladimir Dzhuvinov 
 * @version 2024-04-20
 */
@Immutable
public class Algorithm implements Serializable {


	private static final long serialVersionUID = 1L;


	/**
	 * No algorithm (unsecured JOSE object without signature / encryption).
	 */
	public static final Algorithm NONE = new Algorithm("none", Requirement.REQUIRED);


	/**
	 * The algorithm name.
	 */
	private final String name;


	/**
	 * The implementation requirement, {@code null} if not known.
	 */
	private final Requirement requirement;


	/**
	 * Creates a new JOSE algorithm name.
	 *
	 * @param name The algorithm name. Must not be {@code null}.
	 * @param req  The implementation requirement, {@code null} if not 
	 *             known.
	 */
	public Algorithm(final String name, final Requirement req) {
		this.name = Objects.requireNonNull(name);
		requirement = req;
	}


	/**
	 * Creates a new JOSE algorithm name.
	 *
	 * @param name The algorithm name. Must not be {@code null}.
	 */
	public Algorithm(final String name) {

		this(name, null);
	}


	/**
	 * Gets the name of this algorithm.
	 *
	 * @return The algorithm name.
	 */
	public final String getName() {

		return name;
	}


	/**
	 * Gets the implementation requirement of this algorithm.
	 *
	 * @return The implementation requirement, {@code null} if not known.
	 */
	public final Requirement getRequirement() {

		return requirement;
	}


	/**
	 * Overrides {@code Object.hashCode()}.
	 *
	 * @return The object hash code.
	 */
	@Override
	public final int hashCode() {

		return name.hashCode();
	}


	/**
	 * Overrides {@code Object.equals()}.
	 *
	 * @param object The object to compare to.
	 *
	 * @return {@code true} if the objects have the same value, otherwise
	 *         {@code false}.
	 */
	@Override
	public boolean equals(final Object object) {

		return object instanceof Algorithm &&
			this.toString().equals(object.toString());
	}


	/**
	 * Returns the string representation of this algorithm.
	 *
	 * @see #getName
	 *
	 * @return The string representation.
	 */
	@Override
	public final String toString() {

		return name;
	}


	/**
	 * Returns the JSON string representation of this algorithm.
	 * 
	 * @return The JSON string representation.
	 */
	public final String toJSONString() {
		return  JSONStringUtils.toJSONString(name);
	}
	
	/**
	 * Parses an optional algorithm.
	 *
	 * @param s The string to parse. May be {@code null}.
	 *
	 * @return  The JOSE algorithm, {@code null} if not specified.
	 */
	public static Algorithm parse(final String s) {
	    
		if(s == null) {
			return null;
		} else {
			return new Algorithm(s);
		}
	}
}
