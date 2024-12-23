package NhanVien;

import javacard.framework.APDU;
import javacard.framework.APDUException;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;
public class NhanVien extends Applet implements ExtendedLength
{
	private static byte[] pin, hoTen, ngaySinh,  gioiTinh, image, id, tempHashPrivateKey;
	private static short pinLen, hoTenLen, ngaySinhLen, gioiTinhLen,  imageLen, idLen, pointerImage;
	private static byte PIN_LENGTH = 16;
	private static byte[] balance;
	private static final byte[] state = {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x24, (byte) 0x21};
	private static final byte PIN_CORRECT = 0X00;
	private static final byte INIT_CARD = (byte) 0x00;
	private static final byte CLEAR_CARD = (byte) 0x01;
	private static final byte CHECK_PIN = (byte) 0x02;
	private static final byte UNLOCK_CARD = (byte) 0x03;
	private static final byte CHECK_LOCKED = (byte) 0x04;
	private static final byte GET_INFO = (byte) 0x05;
	private static final byte CHANGE_PIN = (byte) 0x06;
	private static final byte CHANGE_IMAGE = (byte) 0x07;
	private static final byte GET_IMAGE = (byte) 0x08;
	private static final byte UPDATE_INFO = (byte) 0x09;
	private static final byte UPDATE_PIN = (byte) 0x10;
	private static final byte VERIFY = (byte) 0x11;
	private static final byte GET_ID = (byte) 0x12;
	private static final byte DEPOSIT = (byte) 0x13;
	private static final byte GET_BALANCE = (byte) 0x14;
	private static final byte SIGN_DATA = 0X15;
	private static byte bufferExtendAPDU[];
	private final static short MAX_SIZE = (short)32767;
	private final static short MAX_SIZE_EXTEND_APDU = (short)32767;
	private static short lengthExtendAPDU;
	private static short pointerExtendAPDU;
	private OwnerPIN pinManager;
	private MessageDigest sha;
	private AESKey aesKey;
	private byte[] tempHash;
	private RSAPrivateKey privateKey;
	private RSAPublicKey publicKey;
	private Cipher cipher, cipherAES;
	private Signature rsaSig;
	private RandomData randomData;
	private byte[] iv;
	private byte[] tempBuff;
	private KeyPair keyPair;
	private byte[] temp16BArray;
	public static void install(byte[] bArray, short bOffset, byte bLength) 
	{
		new NhanVien().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}
	// khoi tao cac bien va doi tuong can thiet
		public NhanVien(){
		register();
		hoTen = new byte[64];
		pin = new byte[16];
		gioiTinh = new byte[16];
		ngaySinh = new byte[16];
		id = new byte[16];
		pinLen = (byte) 0;
		idLen = (byte) 0;
		hoTenLen = (byte) 0;
		ngaySinhLen = (byte) 0;		
		gioiTinhLen = (byte) 0;
		pointerImage = (short) 0;
        image = new byte[MAX_SIZE];
        imageLen = (byte) 0;
        balance = new byte[4];
        bufferExtendAPDU = new byte[MAX_SIZE_EXTEND_APDU];
        pointerExtendAPDU = 0;
        lengthExtendAPDU = 0;
        pinManager = new OwnerPIN((byte) 3, PIN_LENGTH); // thiet lap so lan sai va do dai PIN
        // khoi tao doi tuong thuc hien bam du lieu
        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);        
        cipherAES = (Cipher) Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);       
                                                                                                                                                                             
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short) 128, false);
        tempHash = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        
        cipher = (Cipher) cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        
        // khoi tao doi tuong thuc hien tao va xac minh chu ky
        rsaSig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false); 
        keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
        keyPair.genKeyPair();
        privateKey = (RSAPrivateKey) keyPair.getPrivate();
        publicKey = (RSAPublicKey) keyPair.getPublic();
        
        tempHashPrivateKey = new byte[128];
		iv = new byte[16];
		randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		randomData.generateData(iv,(short)0 , (short)iv.length);
		// tempBuff also used as 128-byte array holder for decryption
		tempBuff = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT);
		temp16BArray = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
	}
	
	private void sendExtendAPDU(APDU apdu, short length){
		short toSend = lengthExtendAPDU;
		short le = apdu.setOutgoing(); 
		
		apdu.setOutgoingLength(toSend);
		
		short sendLen = 0;
		pointerExtendAPDU = 0;
		while(toSend > 0)
		{
			sendLen = (toSend > le)?le:toSend;

			apdu.sendBytesLong(bufferExtendAPDU, pointerExtendAPDU, sendLen);
			toSend -= sendLen;
			pointerExtendAPDU += sendLen;
		}
	}
	private void receiveExtendAPDU(APDU apdu, short length){
		byte[] buff = apdu.getBuffer();
		lengthExtendAPDU = apdu.getIncomingLength();
		if (lengthExtendAPDU > MAX_SIZE)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		//lay ra vi tri bat dau data
		short dataOffset = apdu.getOffsetCdata();
		pointerExtendAPDU = 0;
		while (length > 0)
		{
			//copy du lieu nhan duoc tu apdu buffer vao mang temp
			Util.arrayCopy(buff, dataOffset, bufferExtendAPDU, pointerExtendAPDU, length);

			pointerExtendAPDU += length;

			//tiep tuc nhan du lieu va ghi vao apdu buffer tai vi tri dataOffset
			length = apdu.receiveBytes(dataOffset);
		}
	}
	private void clearBufferExtendAPDU(){
		Util.arrayFillNonAtomic(bufferExtendAPDU, (short) 0, (short) MAX_SIZE, (byte) 0);
		lengthExtendAPDU = 0;
	}
	private void addToBufferExtendAPDU(byte[] src, short offset, short length){
		Util.arrayCopy(src, offset, bufferExtendAPDU, lengthExtendAPDU, length);
		lengthExtendAPDU += length;
		
	}
	private void generateAESKey(byte[] buf, short offset, short length){
		byte[] truncatedKey = new byte[16];
		sha.doFinal(buf, offset, length, tempHash, (short) 0);
		Util.arrayCopy(tempHash, (short) 0, truncatedKey, (short) 0, (short) 16);
		aesKey.setKey(truncatedKey, (short)0);
	}	
	
    private short decryptAES(byte[] buf, short inOffset, short length){
	    cipherAES.init(aesKey, Cipher.MODE_DECRYPT);
	    return cipherAES.doFinal(buf, inOffset, (short) 128, buf, (short) 0);
    }
    private short encryptAES(byte[] buf, short inOffset, short length){
	    cipherAES.init(aesKey, Cipher.MODE_ENCRYPT);
	    Util.arrayFillNonAtomic(buf, (short) (inOffset + length), (short) (128 - length), (byte)0);
	    return cipherAES.doFinal(buf, inOffset, (short) 128, buf, (short) 0);
    }
    
    private short encryptPrivateKey(){
    	short len = privateKey.getModulus(tempHashPrivateKey, (short) 0);
    	len = encryptAES(tempHashPrivateKey, (short) 0, len);
	    privateKey.setModulus(tempHashPrivateKey, (short) 0, len);
	    return len;
    }
    
    private short decryptPrivateKey(){
    	short len = privateKey.getModulus(tempHashPrivateKey, (short) 0);
    	len = decryptAES(tempHashPrivateKey, (short) 0, len);
	    privateKey.setModulus(tempHashPrivateKey, (short) 0, len);
	    return len;
    }
	

	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buf = apdu.getBuffer();
		// thiet lap nhan du lieu tu apdu co do dai length
		short length = apdu.setIncomingAndReceive();
			
		switch (buf[ISO7816.OFFSET_INS])
		{
		case INIT_CARD:
			initInfo(apdu, length);
			break;
		case CLEAR_CARD: 
			clearCard(apdu, length);
			break;
		case CHECK_PIN:
			checkPin(apdu, length);
			break;
		case UNLOCK_CARD:
			unlockCard(apdu, length);
			break;
		case CHECK_LOCKED:
			checkLocked(apdu);
			break;
		case GET_INFO:
			getInfo(apdu, length);
			break;
		case CHANGE_PIN:
			changePin(apdu, length);
			break;
		case CHANGE_IMAGE:
			changeImage(apdu, length);
			break;
		case GET_IMAGE:
			getImage(apdu, length);
			break;
		case UPDATE_INFO:
			updateInfo(apdu, length);
			break;
		case UPDATE_PIN:
			updatePin(apdu, length);
			break;
		case VERIFY:
			verify(apdu, length);
			break;
		case GET_ID:
			getId(apdu, length);
			break;
		case DEPOSIT:
			deposit(apdu,length);
			break;
		case GET_BALANCE:
			getBalance(apdu,length);
			break;
		case SIGN_DATA:
			sign_data(apdu, buf, length);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
	// khoi tao thong tin the
	private void initInfo(APDU apdu, short length){
		byte[] buffer = apdu.getBuffer();
		receiveExtendAPDU(apdu, length);
		byte keyCharCounter = (byte) 0;
		byte keyChar = (byte) '$';
		for (short i = (short) 0; i< lengthExtendAPDU; i++){
			if(bufferExtendAPDU[i] == keyChar){
				keyCharCounter++;
			} else{
					switch(keyCharCounter){
						case (byte) 0: {
							id[idLen] = bufferExtendAPDU[i];
							idLen++;
							break;
						}
						case (byte) 1: {
							hoTen[hoTenLen] = bufferExtendAPDU[i];
							hoTenLen++;
							break;
						}
						case (byte) 2: {
							ngaySinh[ngaySinhLen] = bufferExtendAPDU[i];
							ngaySinhLen++;
							break;
						}
						case (byte) 3: {
							gioiTinh[gioiTinhLen] = bufferExtendAPDU[i];
							gioiTinhLen++;
							break;
						}
						case (byte) 4: {
							pin[pinLen] = bufferExtendAPDU[i];
							pinLen++;
							break;
						}
						
						default: {
							
							break;
						}
				}
			}
		}
		generateAESKey(pin, (short)0, pinLen);
		// encryptAes(id,idLen);
		hoTen = encryptAes(hoTen, hoTenLen);
		ngaySinh = encryptAes(ngaySinh, ngaySinhLen);
		gioiTinh = encryptAes(gioiTinh, gioiTinhLen);
		pin = encryptAes(pin,pinLen);		
		pinManager.update(pin, (short) 0, PIN_LENGTH);
		short modLength = publicKey.getModulus(buffer, (short)0);
		short exLength = publicKey.getExponent(buffer, modLength);
		apdu.setOutgoingAndSend((short)0,(short)(modLength + exLength));
		
		clearBufferExtendAPDU();
	}

	private void updateInfo(APDU apdu, short length){
		byte[] buffer = apdu.getBuffer();
		clearBufferExtendAPDU();
		receiveExtendAPDU(apdu, length);
        // dem so luong thong tin len
		byte keyCharCounter = (byte) 0;
		byte keyChar = (byte) '$';
		Util.arrayFillNonAtomic(id, (short) 0, (short) 16, (byte) 0);
		Util.arrayFillNonAtomic(hoTen, (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(ngaySinh, (short) 0, (short) 16, (byte) 0);
        Util.arrayFillNonAtomic(gioiTinh, (short) 0, (short) 16, (byte) 0);
        idLen = (short) 0;
		hoTenLen = (short) 0;		
		ngaySinhLen = (short) 0;
		gioiTinhLen = (short) 0;
		for (short i = (short) 0; i< lengthExtendAPDU; i++){
			if(bufferExtendAPDU[i] == keyChar){
				keyCharCounter++;
			} else{
					switch(keyCharCounter){
						case (byte) 0: {
							id[idLen] = bufferExtendAPDU[i];
							idLen++;
							break;
						}
						case (byte) 1: {
							hoTen[hoTenLen] = bufferExtendAPDU[i];
							hoTenLen++;
							break;
						}
						case (byte) 2: {
							ngaySinh[ngaySinhLen] = bufferExtendAPDU[i];
							ngaySinhLen++;
							break;
						}
						case (byte) 3: {
							gioiTinh[gioiTinhLen] = bufferExtendAPDU[i];
							gioiTinhLen++;
							break;
						}
						default: {
							break;
						}
				}
			}
		}
		// encryptAES(hoTen, (short) 0, hoTenLen);
		// encryptAES(ngaySinh, (short)0, ngaySinhLen);
		// encryptAES(gioiTinh, (short) 0, gioiTinhLen);
		clearBufferExtendAPDU();
	}
	

	private void clearCard(APDU apdu, short length) {
        pinLen = (short) 0;
        hoTenLen = (short) 0;
        ngaySinhLen = (short) 0;
        gioiTinhLen = (short) 0;
        idLen = (short) 0;
        imageLen = (short) 0;
        
        Util.arrayFillNonAtomic(hoTen, (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(ngaySinh, (short) 0, (short) 16, (byte) 0);
        Util.arrayFillNonAtomic(gioiTinh, (short) 0, (short) 16, (byte) 0);
        Util.arrayFillNonAtomic(id, (short) 0, (short) 16, (byte) 0);
        Util.arrayFillNonAtomic(pin, (short) 0, (short) 16, (byte) 0);
        
        privateKey.clearKey();
        aesKey.clearKey();
    }
    
    private void verify(APDU apdu, short length){
	    clearBufferExtendAPDU();
	    receiveExtendAPDU(apdu, length);
	    
		decryptPrivateKey();
		
	    
        rsaSig.init(privateKey, Signature.MODE_SIGN);
        lengthExtendAPDU = rsaSig.sign(bufferExtendAPDU, (short) 0, lengthExtendAPDU, bufferExtendAPDU, (short) 1);
        lengthExtendAPDU+= (short) 1;
	    bufferExtendAPDU[(byte) 0] = (byte) 1;
        
        sendExtendAPDU(apdu, length);
        
        encryptPrivateKey();
    }
    
    private void checkPin(APDU apdu, short length) {
    	byte[] buf = apdu.getBuffer();
    	Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, tempBuff, (short)0, length);
    	byte[] temp = encryptAes(tempBuff,length);
		if (!pinManager.check(temp, (short)0, PIN_LENGTH)) {
            short triesRemaining = pinManager.getTriesRemaining();
            if (triesRemaining == 0) {
                ISOException.throwIt((short) 0x6300); // The bi khoa
            }
            ISOException.throwIt((short) (0x6300 | triesRemaining)); // Tra ve so lan nhap sai
        }

        buf[0] = PIN_CORRECT;	// Tra ve 00
        unlockCard(apdu, length);
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }
    
    private void updatePin(APDU apdu, short length){
	    byte[] buf = apdu.getBuffer();
	    
	    if(length != PIN_LENGTH){
		    APDUException.throwIt(APDUException.BAD_LENGTH);
	    }
	    Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, pin, (short) 0, PIN_LENGTH);
	    pinManager.update(pin, (short) 0, PIN_LENGTH);
    }
    
    private void checkLocked(APDU apdu) {
		byte[] buf = apdu.getBuffer();

		if (pinManager.getTriesRemaining() == 0) {
			buf[0] = (byte) 0x01; // The bi khoa
		} else {
			buf[0] = (byte) 0x00; // The khong bi khoa
		}

		apdu.setOutgoingAndSend((short) 0, (short) 1);
	}
    
    private void unlockCard(APDU apdu, short length){
	    pinManager.resetAndUnblock();
    }

    private void getId(APDU apdu, short length){
	    clearBufferExtendAPDU();
	    if(idLen > 0){
			decryptAES(id, (short) 0, idLen);
			addToBufferExtendAPDU(id, (short) 0, idLen);
			encryptAES(id, (short) 0, idLen);   
	    }
		    sendExtendAPDU(apdu, length);
    }
    
    private void getInfo(APDU apdu, short length){
	    byte[] buffer = apdu.getBuffer();
	    clearBufferExtendAPDU();
	    
	    addToBufferExtendAPDU(id, (short) 0, idLen);
	    
        addToBufferExtendAPDU(state, (short) 3, (short) 1);
        
	    Util.arrayCopy(hoTen, (short)0, tempBuff, (short)0, (short)hoTen.length);
	    decryptAes(tempBuff);
        addToBufferExtendAPDU(tempBuff, (short) 0, hoTenLen);
       
        addToBufferExtendAPDU(state, (short) 3, (short) 1);
        
	    Util.arrayCopy(ngaySinh, (short)0, temp16BArray, (short)0, (short)16);
	    decryptAes(temp16BArray);
        addToBufferExtendAPDU(temp16BArray, (short) 0, ngaySinhLen);
        
        addToBufferExtendAPDU(state, (short) 3, (short) 1);
        
		Util.arrayCopy(gioiTinh, (short)0, temp16BArray, (short)0, (short)16);
	    decryptAes(temp16BArray);
        addToBufferExtendAPDU(temp16BArray, (short) 0, gioiTinhLen);
        
        addToBufferExtendAPDU(state, (short) 3, (short) 1);
        
        addToBufferExtendAPDU(balance, (short)0, (byte)balance.length);
        addToBufferExtendAPDU(state, (short)0, (short)1);
        sendExtendAPDU(apdu, length);
    }

	private void getBalance(APDU apdu, short length){
	    clearBufferExtendAPDU();
        addToBufferExtendAPDU(balance, (short)0, (byte)balance.length);
        sendExtendAPDU(apdu, length);
    }

    private void changePin(APDU apdu, short length){
	    byte[] buffer = apdu.getBuffer(); 
	    Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, pin, (short) 0,length);
	    pinLen = length;
    }
	private void changeImage(APDU apdu, short length){
		byte[] buf = apdu.getBuffer();
		// p2 = 0 -> gui lan dau, p2 = 1 
		byte p2 = buf[ISO7816.OFFSET_P2];
		if(p2 == (byte) 0x00){
			imageLen = (short)0;
		}
		receiveExtendAPDU(apdu, length);
		// encryptAES(bufferExtendAPDU, (short) 0, lengthExtendAPDU);
		Util.arrayCopy(bufferExtendAPDU, (short) 0, image, imageLen, lengthExtendAPDU);
		imageLen += lengthExtendAPDU;
		clearBufferExtendAPDU();
	}
	
	private void getImage(APDU apdu, short length){
		clearBufferExtendAPDU();
		if(pointerImage >= imageLen){
			pointerImage = 0;
		} else {
			lengthExtendAPDU = (short) ((imageLen - pointerImage) > 128 ? 128 : imageLen - pointerImage);
			Util.arrayCopy(image, pointerImage, bufferExtendAPDU, (short) 0, lengthExtendAPDU);
			pointerImage += (short) lengthExtendAPDU;
			// decryptAES(bufferExtendAPDU, (short) 0, lengthExtendAPDU);
			sendExtendAPDU(apdu, length);
		}
	}
	private void deposit(APDU apdu,short length){
		byte[] buf = apdu.getBuffer();
		JCSystem.beginTransaction();
		byte count = 3;
		byte carrier = 0;
		short temp;
		while(count >= 0){
			temp = (short) ((buf[ISO7816.OFFSET_CDATA + count] & 0xFF) + (balance[count] & 0xFF) + carrier);
			carrier = (byte) ((temp > 0xFF) ? 1 : 0); 
			balance[count] = (byte) (temp & 0xFF);   
			count--;
		}
		if (carrier != 0) { // Overflow check after processing all bytes
			JCSystem.abortTransaction();
			APDUException.throwIt(APDUException.IO_ERROR);
		}
		JCSystem.commitTransaction();
	}
	private byte padData(byte[] dataToPad, short length) {
		byte padLength = (byte) (16 - (length % 16));
		for (short i = (short) length; i < (short) (length + padLength); i++) {
			dataToPad[i] = padLength; 
		}
		return (byte)(padLength + length);
    }
	private byte[] encryptAes(byte[] dataToEncrypt,short length) {
    	byte padLength = padData(dataToEncrypt, length);
    	byte[] encryptedData = new byte[padLength];
		cipherAES.init(aesKey, Cipher.MODE_ENCRYPT);
		cipherAES.doFinal(dataToEncrypt, (short) 0, (short) padLength, encryptedData, (short) 0);
		return encryptedData;
    }
    private void decryptAes(byte[] dataToDecrypt){
	    cipherAES.init(aesKey,Cipher.MODE_DECRYPT);
	    cipherAES.doFinal(dataToDecrypt, (short)0, (short)dataToDecrypt.length, dataToDecrypt, (short)0);
    }
    private void sign_data(APDU apdu, byte[] buf, short dataLength) {
	    byte[] dataToSign = new byte[dataLength];
	    Util.arrayCopy(buf, ISO7816.OFFSET_CDATA, dataToSign, (short) 0, dataLength);
	    byte[] signedData = signRsa(dataToSign);
	    Util.arrayCopy(signedData, (short) 0, buf, (short) 0, (short) signedData.length);
	    apdu.setOutgoingAndSend((short) 0, (short) signedData.length);
    }
    
    
    private byte[] signRsa(byte[] dataToSign) {
	    rsaSig.init(privateKey, Signature.MODE_SIGN);
	    byte[] signedBuffer = new byte[(short) (KeyBuilder.LENGTH_RSA_1024 / 8)];
	    rsaSig.sign(dataToSign, (short) 0, (short) dataToSign.length, signedBuffer, (short) 0);
	    return signedBuffer;
    }
}

