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

package com.nimbusds.jose.crypto.impl;


import com.nimbusds.jose.JOSEException;
import net.jcip.annotations.ThreadSafe;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;


/**
 * RSAES OAEP with SHA-256, SHA-384 and SHA-512 methods for Content Encryption
 * Key (CEK) encryption and decryption. This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @author Peter Laurina
 * @author Pankaj Yadav
 * @version 2024-09-10
 */
@ThreadSafe
public class RSA_OAEP_SHA2 {
	
	
	/**
	 * The JCA algorithm name for RSA-OAEP-256.
	 */
	private static final String RSA_OEAP_256_JCA_ALG = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
	
	
	/**
	 * The JCA algorithm name for RSA-OAEP-384.
	 */
	private static final String RSA_OEAP_384_JCA_ALG = "RSA/ECB/OAEPWithSHA-384AndMGF1Padding";
	
	
	/**
	 * The JCA algorithm name for RSA-OAEP-512.
	 */
	private static final String RSA_OEAP_512_JCA_ALG = "RSA/ECB/OAEPWithSHA-512AndMGF1Padding";
	
	
	/**
	 * The JCA algorithm name for SHA-256.
	 */
	private static final String SHA_256_JCA_ALG = "SHA-256";
	
	
	/**
	 * The JCA algorithm name for SHA-384.
	 */
	private static final String SHA_384_JCA_ALG = "SHA-384";
	
	/**
	 * The JCA algorithm name for SHA-512.
	 */
	private static final String SHA_512_JCA_ALG = "SHA-512";
	
	
	/**
	 * Encrypts the specified Content Encryption Key (CEK).
	 *
	 * @param pub        The public RSA key. Must not be {@code null}.
	 * @param cek        The Content Encryption Key (CEK) to encrypt. Must
	 *                   not be {@code null}.
	 * @param shaBitSize The SHA-2 bit size. Must be 256, 384 or 512.
	 * @param provider   The JCA provider, {@code null} to use the
	 *                   default.
	 *
	 * @return The encrypted Content Encryption Key (CEK).
	 *
	 * @throws JOSEException If encryption failed.
	 */
	public static byte[] encryptCEK(final RSAPublicKey pub,
					final SecretKey cek,
					final int shaBitSize,
					final Provider provider)
		throws JOSEException {
		
		final String jcaAlgName;
		final String jcaShaAlgName;
		final MGF1ParameterSpec mgf1ParameterSpec;
		if (256 == shaBitSize) {
			jcaAlgName = RSA_OEAP_256_JCA_ALG;
			jcaShaAlgName = SHA_256_JCA_ALG;
			mgf1ParameterSpec = MGF1ParameterSpec.SHA256;
		} else if (384 == shaBitSize) {
			jcaAlgName = RSA_OEAP_384_JCA_ALG;
			jcaShaAlgName = SHA_384_JCA_ALG;
			mgf1ParameterSpec = MGF1ParameterSpec.SHA384;
		} else if (512 == shaBitSize) {
			jcaAlgName = RSA_OEAP_512_JCA_ALG;
			jcaShaAlgName = SHA_512_JCA_ALG;
			mgf1ParameterSpec = MGF1ParameterSpec.SHA512;
		} else {
			throw new JOSEException("Unsupported SHA-2 bit size: " + shaBitSize);
		}
		
		try {
			AlgorithmParameters algp = AlgorithmParametersHelper.getInstance("OAEP", provider);
			AlgorithmParameterSpec paramSpec = new OAEPParameterSpec(jcaShaAlgName, "MGF1", mgf1ParameterSpec, PSource.PSpecified.DEFAULT);
			algp.init(paramSpec);
			Cipher cipher = CipherHelper.getInstance(jcaAlgName, provider);
			cipher.init(Cipher.WRAP_MODE, pub, algp);
			return cipher.wrap(cek);

		} catch (InvalidKeyException e) {
			throw new JOSEException("Encryption failed due to invalid RSA key for SHA-" + shaBitSize + ": "
				+ "The RSA key may be too short, use a longer key", e);
		} catch (Exception e) {
			// java.security.NoSuchAlgorithmException
			// java.security.NoSuchPaddingException
			// javax.crypto.IllegalBlockSizeException
			// javax.crypto.BadPaddingException
			throw new JOSEException(e.getMessage(), e);
		}
	}
	
	
	/**
	 * Decrypts the specified encrypted Content Encryption Key (CEK).
	 *
	 * @param priv         The private RSA key. Must not be {@code null}.
	 * @param encryptedCEK The encrypted Content Encryption Key (CEK) to
	 *                     decrypt. Must not be {@code null}.
	 * @param shaBitSize   The SHA-2 bit size. Must be 256 or 512.
	 * @param provider     The JCA provider, {@code null} to use the
	 *                     default.
	 *
	 * @return The decrypted Content Encryption Key (CEK).
	 *
	 * @throws JOSEException If decryption failed.
	 */
	public static SecretKey decryptCEK(final PrivateKey priv,
					   final byte[] encryptedCEK,
					   final int shaBitSize,
					   final Provider provider)
		throws JOSEException {
		
		final String jcaAlgName;
		final String jcaShaAlgName;
		final MGF1ParameterSpec mgf1ParameterSpec;
		if (256 == shaBitSize) {
			jcaAlgName = RSA_OEAP_256_JCA_ALG;
			jcaShaAlgName = SHA_256_JCA_ALG;
			mgf1ParameterSpec = MGF1ParameterSpec.SHA256;
		} else if (384 == shaBitSize) {
			jcaAlgName = RSA_OEAP_384_JCA_ALG;
			jcaShaAlgName = SHA_384_JCA_ALG;
			mgf1ParameterSpec = MGF1ParameterSpec.SHA384;
		} else if (512 == shaBitSize) {
			jcaAlgName = RSA_OEAP_512_JCA_ALG;
			jcaShaAlgName = SHA_512_JCA_ALG;
			mgf1ParameterSpec = MGF1ParameterSpec.SHA512;
		} else {
			throw new JOSEException("Unsupported SHA-2 bit size: " + shaBitSize);
		}
		
		try {
			AlgorithmParameters algp = AlgorithmParametersHelper.getInstance("OAEP", provider);
			AlgorithmParameterSpec paramSpec = new OAEPParameterSpec(jcaShaAlgName, "MGF1", mgf1ParameterSpec, PSource.PSpecified.DEFAULT);
			algp.init(paramSpec);
			Cipher cipher = CipherHelper.getInstance(jcaAlgName, provider);
			cipher.init(Cipher.UNWRAP_MODE, priv, algp);
			return (SecretKey) cipher.unwrap(encryptedCEK, "AES", Cipher.SECRET_KEY);
			
		} catch (Exception e) {
			// java.security.NoSuchAlgorithmException
			// java.security.NoSuchPaddingException
			// java.security.InvalidKeyException
			// javax.crypto.IllegalBlockSizeException
			// javax.crypto.BadPaddingException
			throw new JOSEException(e.getMessage(), e);
		}
	}
	
	
	/**
	 * Prevents public instantiation.
	 */
	private RSA_OAEP_SHA2() { }
}