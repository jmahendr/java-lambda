package com.amazonaws.lambda.demo;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.S3Event;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GetObjectRequest;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.util.IOUtils;

public class LambdaFunctionHandler implements RequestHandler<S3Event, String> {

	private AmazonS3 s3 = AmazonS3ClientBuilder.standard().build();

	public LambdaFunctionHandler() {
	}

	// Test purpose only.
	LambdaFunctionHandler(AmazonS3 s3) {
		this.s3 = s3;
	}

	@Override
	public String handleRequest(S3Event event, Context context) {

		String returnMsg = "";
		String destinationBucket = System.getenv("destination_bucket");
		String pgpPublicKeyBucket = System.getenv("public_key_bucket");
		String pgpPublicKeyObject = System.getenv("public_key_file");
		context.getLogger().log(destinationBucket);
		context.getLogger().log("Received event: " + event);

		// Get the object from the event
		String bucket = event.getRecords().get(0).getS3().getBucket().getName();
		String key = event.getRecords().get(0).getS3().getObject().getKey();
		context.getLogger().log(bucket + "." + key + " received.");

		//
		try {

			S3Object keyResponse = s3.getObject(new GetObjectRequest(pgpPublicKeyBucket, pgpPublicKeyObject));
			InputStream keyInputStr = (InputStream) keyResponse.getObjectContent();
			PGPPublicKey pubKey = readPublicKey(keyInputStr);

			S3Object response = s3.getObject(new GetObjectRequest(bucket, key));
			String contentType = response.getObjectMetadata().getContentType();
			context.getLogger().log("CONTENT TYPE: " + contentType);
			returnMsg = contentType;

			InputStream inputStr = (InputStream) response.getObjectContent();
			// s3.putObject(destinationBucket, key, inputStr, new ObjectMetadata());

			byte[] bytes = IOUtils.toByteArray(inputStr);

			byte[] encrypted = this.createRsaEncryptedObject(pubKey, bytes);

			/*
			 * BufferedReader reader = new BufferedReader(new InputStreamReader(inputStr));
			 * String line; while ((line = reader.readLine()) != null) {
			 * context.getLogger().log(line); }
			 */
			return contentType;
		} catch (Exception e) {
			e.printStackTrace();
			context.getLogger().log(String.format("Error getting object %s from bucket %s. Make sure they exist and"
					+ " your bucket is in the same region as this function.", key, bucket));
		}
		return returnMsg;
	}

	public byte[] createRsaEncryptedObject(PGPPublicKey encryptionKey, byte[] data) throws PGPException, IOException {

		ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
		OutputStream pOut = lData.open(bOut, PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, data.length, new Date());
		pOut.write(data);
		pOut.close();
		byte[] plainText = bOut.toByteArray();

		ByteArrayOutputStream encOut = new ByteArrayOutputStream();
		PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
				new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256).setWithIntegrityPacket(true)
						.setSecureRandom(new SecureRandom()).setProvider("BCFIPS"));
		encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey).setProvider("BCFIPS"));

		OutputStream cOut = encGen.open(encOut, plainText.length);
		cOut.write(plainText);
		cOut.close();

		return encOut.toByteArray();
	}

	public PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {
		in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection((Collection<PGPPublicKeyRing>) in);
		PGPPublicKey key = null;

		Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();

		while (key == null && rIt.hasNext()) {
			PGPPublicKeyRing kRing = rIt.next();
			Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
			while (key == null && kIt.hasNext()) {
				PGPPublicKey k = kIt.next();
				if (k.isEncryptionKey()) {
					key = k;
				}
			}
		}

		if (key == null) {
			throw new IllegalArgumentException("Can't find encryption key in key ring.");
		}

		return key;
	}
}