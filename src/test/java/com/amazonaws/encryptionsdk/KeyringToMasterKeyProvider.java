package com.amazonaws.encryptionsdk;

import AwsKmsDiscoveryKeyring_Compile.AwsKmsDiscoveryKeyring;
import AwsKmsKeyring_Compile.AwsKmsKeyring;
import AwsKmsMrkDiscoveryKeyring_Compile.AwsKmsMrkDiscoveryKeyring;
import AwsKmsMrkKeyring_Compile.AwsKmsMrkKeyring;
import DefaultCMM_Compile.DefaultCMM;
import MultiKeyring_Compile.MultiKeyring;
import RawAESKeyring_Compile.RawAESKeyring;
import RawRSAKeyring_Compile.RawRSAKeyring;
import com.amazonaws.encryptionsdk.exception.NoSuchMasterKeyException;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.amazonaws.encryptionsdk.kms.DiscoveryFilter;
import com.amazonaws.encryptionsdk.kmssdkv2.AwsKmsMrkAwareMasterKeyProvider;
import com.amazonaws.encryptionsdk.kmssdkv2.KmsMasterKeyProvider;
import com.amazonaws.encryptionsdk.multi.MultipleProviderFactory;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import software.amazon.awssdk.regions.Region;
import software.amazon.cryptography.materialproviders.ToNative;
import software.amazon.cryptography.materialproviders.internaldafny.types.ICryptographicMaterialsManager;
import software.amazon.cryptography.materialproviders.internaldafny.types.IKeyring;
import software.amazon.cryptography.primitives.internaldafny.types.RSAPaddingMode;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static software.amazon.smithy.dafny.conversion.ToNative.Simple.ByteBuffer;
import static software.amazon.smithy.dafny.conversion.ToNative.Simple.String;

public class KeyringToMasterKeyProvider {

	public static MasterKeyProvider<?> createMasterKeyProvider(ICryptographicMaterialsManager cmm) {
		// TODO-Java-MKP: Handle CMMs to Java CMM/MKP,
		//  also for Required EC CMM(Not supported for MKP, try to replicate if possible)

		if (cmm instanceof DefaultCMM) {
			DefaultCMM defaultCmm = (DefaultCMM) cmm;
			return createMasterKeyProvider(defaultCmm.keyring());
		}
		return null;
	}

	public static MasterKeyProvider<?> createMasterKeyProvider(IKeyring keyring) {
		if (keyring == null) {
			throw new IllegalArgumentException("Keyring cannot be null");
		}

		if (keyring instanceof AwsKmsKeyring) {
			AwsKmsKeyring kmsKeyring = (AwsKmsKeyring) keyring;
			String kmsKeyArn = String(kmsKeyring.awsKmsKey());
			return KmsMasterKeyProvider.builder()
					.buildStrict(kmsKeyArn);

		} else if (keyring instanceof AwsKmsMrkKeyring) {
			AwsKmsMrkKeyring mrkKeyring = (AwsKmsMrkKeyring) keyring;
			String kmsKeyArn = String(mrkKeyring.awsKmsKey());
			return AwsKmsMrkAwareMasterKeyProvider.builder()
					.buildStrict(Collections.singletonList(kmsKeyArn));

		} else if (keyring instanceof AwsKmsDiscoveryKeyring) {
			AwsKmsDiscoveryKeyring discoveryKeyring = (AwsKmsDiscoveryKeyring) keyring;
			if (discoveryKeyring.discoveryFilter().is_Some()) {
				software.amazon.cryptography.materialproviders.model.DiscoveryFilter mplFilter = ToNative.DiscoveryFilter(discoveryKeyring.discoveryFilter().dtor_value());
				return KmsMasterKeyProvider.builder().buildDiscovery(new DiscoveryFilter(mplFilter.partition(), mplFilter.accountIds()));
			}
			return KmsMasterKeyProvider.builder()
					.buildDiscovery();
		} else if (keyring instanceof AwsKmsMrkDiscoveryKeyring) {
			AwsKmsMrkDiscoveryKeyring mrkDiscoveryKeyring = (AwsKmsMrkDiscoveryKeyring) keyring;
			String mrkRegion = String(mrkDiscoveryKeyring.region());
			if (mrkDiscoveryKeyring.discoveryFilter().is_Some()) {
				software.amazon.cryptography.materialproviders.model.DiscoveryFilter mplFilter = ToNative.DiscoveryFilter(mrkDiscoveryKeyring.discoveryFilter().dtor_value());
				return AwsKmsMrkAwareMasterKeyProvider.builder()
						.discoveryMrkRegion(Region.of(mrkRegion))
						.buildDiscovery(new DiscoveryFilter(mplFilter.partition(), mplFilter.accountIds()));
			}
			return AwsKmsMrkAwareMasterKeyProvider.builder()
					.discoveryMrkRegion(Region.of(mrkRegion))
					.buildDiscovery();
		} else if (keyring instanceof RawAESKeyring) {
			RawAESKeyring aesKeyring = (RawAESKeyring) keyring;
			ByteBuffer keyByteBuffer = ByteBuffer(aesKeyring.wrappingKey());
			ByteBuffer provider = ByteBuffer(aesKeyring.keyNamespace());
			ByteBuffer keyId = ByteBuffer(aesKeyring.keyName());

			return JceMasterKey.getInstance(
					new SecretKeySpec(keyByteBuffer.array(), "AES"),
					new String(provider.array(), StandardCharsets.UTF_8),
					new String(keyId.array(), StandardCharsets.UTF_8),
					"AES/GCM/NOPADDING");
		} else if (keyring instanceof RawRSAKeyring) {
			RawRSAKeyring rsaKeyring = (RawRSAKeyring) keyring;

			PublicKey wrappingKey = null;
			PrivateKey unwrappingKey = null;
			ByteBuffer provider = ByteBuffer(rsaKeyring.keyNamespace());
			ByteBuffer keyId = ByteBuffer(rsaKeyring.keyName());
			if (rsaKeyring.publicKey().is_Some()) {
				wrappingKey = getPublicKeyFromPEM(ByteBuffer(rsaKeyring.publicKey().dtor_value()));
			}
			if (rsaKeyring.privateKey().is_Some()) {
				unwrappingKey = getPrivateKeyFromPEM(ByteBuffer(rsaKeyring.privateKey().dtor_value()));
			}
			String rsaWrappingAlg = getRsaWrappingAlg(rsaKeyring.paddingScheme());
			if (wrappingKey == null || unwrappingKey == null) {
				throw new NoSuchMasterKeyException("No Public Key or Private found to encrypt/decrypt with Master Key.");
			}

			return JceMasterKey.getInstance(
					wrappingKey,
					unwrappingKey,
					new String(provider.array(), StandardCharsets.UTF_8),
					new String(keyId.array(), StandardCharsets.UTF_8),
					rsaWrappingAlg);

		} else if (keyring instanceof MultiKeyring) {
			MultiKeyring multiKeyring = (MultiKeyring) keyring;
			List<MasterKeyProvider<?>> providers = new ArrayList<>();

			// Convert generator keyring if present
			if (multiKeyring.generatorKeyring().is_Some()) {
				providers.add(createMasterKeyProvider(multiKeyring.generatorKeyring().dtor_value()));
			}

			// Convert child keyrings
			for (IKeyring child : multiKeyring.childKeyrings()) {
				providers.add(createMasterKeyProvider(child));
			}
			return MultipleProviderFactory.buildMultiProvider(providers);
		} else {
			// Return null for Keyrings which are not supported by Master Key Provider
			return null;
		}
	}

	public static String getRsaWrappingAlg(RSAPaddingMode paddingScheme) {
		if (paddingScheme.is_PKCS1()) {
			return "RSA/ECB/PKCS1Padding";
		} else if (paddingScheme.is_OAEP__SHA1()) {
			return "RSA/ECB/OAEPWithSHA-1AndMGF1Padding";
		} else if (paddingScheme.is_OAEP__SHA256()) {
			return "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
		} else if (paddingScheme.is_OAEP__SHA384()) {
			return "RSA/ECB/OAEPWithSHA-384AndMGF1Padding";
		} else if (paddingScheme.is_OAEP__SHA512()) {
			return "RSA/ECB/OAEPWithSHA-512AndMGF1Padding";
		} else {
			throw new IllegalArgumentException("Unsupported RSA padding scheme: " + paddingScheme.getClass().getName());
		}
	}

	// Helper methods to create keys from byte arrays
	public static PublicKey getPublicKeyFromPEM(ByteBuffer pemBuffer) {
		try {
			String pemString = StandardCharsets.UTF_8.decode(pemBuffer).toString();
			PemReader pemReader = new PemReader(new StringReader(pemString));
			PemObject pemObject = pemReader.readPemObject();
			pemReader.close();

			if (!pemObject.getType().equals("PUBLIC KEY")) {
				throw new IllegalArgumentException("Not a public key PEM");
			}

			byte[] x509Key = parsePem(pemString);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // or appropriate algorithm
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(x509Key);
			return keyFactory.generatePublic(keySpec);

		} catch (IOException e) {
			throw new RuntimeException("IOException while reading public key PEM", e);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException("Error generating public key from PEM", e);
		}
	}

	public static PrivateKey getPrivateKeyFromPEM(ByteBuffer pemBuffer) {
		try {
			String pemString = StandardCharsets.UTF_8.decode(pemBuffer).toString();
			PemReader pemReader = new PemReader(new StringReader(pemString));
			PemObject pemObject = pemReader.readPemObject();
			pemReader.close();

			if (!pemObject.getType().equals("PRIVATE KEY")) {
				throw new IllegalArgumentException("Not a private key PEM");
			}

			byte[] pkcs8Key = parsePem(pemString);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // or appropriate algorithm
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Key);
			return keyFactory.generatePrivate(keySpec);

		} catch (IOException e) {
			throw new RuntimeException("IOException while reading private key PEM", e);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException("Error generating private key from PEM", e);
		}
	}

	private static byte[] parsePem(String pem) {
		final String stripped = pem.replaceAll("-+[A-Z ]+-+", "");
		return Base64.decode(stripped);
	}
}
