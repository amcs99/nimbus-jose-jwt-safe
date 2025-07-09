module com.nimbusds.jose.jwt {

	requires jdk.crypto.ec; // TODO: remove when this project targets JDK > 22, see JDK-8312267
	requires jdk.crypto.cryptoki;

	// shaded:
	requires static com.google.gson;
	requires static jcip.annotations;

	// optional:
	requires static com.google.crypto.tink;
	requires static org.bouncycastle.pkix;
	requires static org.bouncycastle.provider;

	exports com.nimbusds.jose;
	exports com.nimbusds.jose.crypto;
	exports com.nimbusds.jose.crypto.bc;
	exports com.nimbusds.jose.crypto.factories;
	exports com.nimbusds.jose.crypto.impl;
	exports com.nimbusds.jose.crypto.opts;
	exports com.nimbusds.jose.crypto.utils;
	exports com.nimbusds.jose.jca;
	exports com.nimbusds.jose.jwk;
	exports com.nimbusds.jose.jwk.gen;
	exports com.nimbusds.jose.jwk.source;
	exports com.nimbusds.jose.mint;
	exports com.nimbusds.jose.proc;
	exports com.nimbusds.jose.produce;
	exports com.nimbusds.jose.util;
	exports com.nimbusds.jose.util.cache;
	exports com.nimbusds.jose.util.events;
	exports com.nimbusds.jose.util.health;
	exports com.nimbusds.jwt;
	exports com.nimbusds.jwt.proc;
	exports com.nimbusds.jwt.util;
}
