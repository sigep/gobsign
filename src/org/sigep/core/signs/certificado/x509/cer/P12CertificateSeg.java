package org.sigep.core.signs.certificado.x509.cer;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import org.sigep.core.signs.certificado.util.Properties;
import org.sigep.core.signs.certificado.util.DataStream;

/**
 * @author rcoarite
 */
public class P12CertificateSeg
{
    private PrivateKey privateKey;
    private X509CertificateSeg certificateSeg;
    private KeyStore keyStore;
    private String password;
    
    /**
     * Crea una nueva instancia del P12CertificateSeg en base al X509CertificateSeg (certificado con la llave pública), la clave privada y el password 
     * @param keyStore almacen de llaves para la generación de llaves en formato P12
     * @param x509CertificateSeg certicado en formato PEM
     * @param privateKey es la llave privada
     * @param password para cifrar el certificado en formato P12
     * @return 
     */
    public static P12CertificateSeg newInstance(KeyStore keyStore, X509CertificateSeg x509CertificateSeg,PrivateKey privateKey,String password)
    {
        P12CertificateSeg certificateSeg = new P12CertificateSeg();
        certificateSeg.certificateSeg = x509CertificateSeg;
        certificateSeg.keyStore = keyStore;
        certificateSeg.privateKey = privateKey;
        certificateSeg.password = password;
        return certificateSeg;
    }
    
    /**
     * Carga un certificado P12 desde una path y el password certificado en formato P12
     * @param pathp12File Es la ruta en que se encuentra el certificado P12
     * @param password para cifrar el certificado en formato P12
     * @return un objeto P12CertificateSeg
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableKeyException 
     */
    public static P12CertificateSeg load(String pathp12File,String password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException
    {
        return load(new FileInputStream(pathp12File), password);
    }
    
    /**
     * Carga un certificado a partir de otro archivo en formato P12 y su contraseña
     * @param p12File el certificado en formato P12
     * @param password para cifrar el certificado en formato P12
     * @return un objeto P12CertificateSeg
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableKeyException 
     */
    public static P12CertificateSeg load(File p12File,String password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException
    {
        return load(new FileInputStream(p12File), password);
    }
    
    /**
     * Carga un certificado en base a un InputStream y password respectivo
     * @param inputStream Flujo de entrada que representa el certificado en formato p12
     * @param password la contraseña del certificado en formato p12
     * @return el objeto certificado en formato P12
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws UnrecoverableKeyException 
     */
    public static P12CertificateSeg load(InputStream inputStream,String password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException
    {
        // Creando la instancia del certificado
        P12CertificateSeg p12CertificateSeg = new P12CertificateSeg();
        
        p12CertificateSeg.password = password;
        
        KeyStore inStore = KeyStore.getInstance("PKCS12");
        p12CertificateSeg.keyStore = inStore;
        inStore.load(inputStream,password.toCharArray());
        PrivateKey  privateKey = (PrivateKey)inStore.getKey(Properties.ALIAS_KEY,password.toCharArray());
        p12CertificateSeg.privateKey = privateKey;

        Certificate[] inChain = inStore.getCertificateChain(Properties.ALIAS_KEY);
        Certificate cerDem = inChain[0];
        X509CertificateSeg x509CertificateSeg = X509CertificateSeg.load(cerDem);
        p12CertificateSeg.certificateSeg = x509CertificateSeg;
        return p12CertificateSeg;
    }

    /**
     * Obtiene la llave privada del certificado
     * @return la llave privada
     */
    public PrivateKey getPrivateKey()
    {
        return privateKey;
    }

    /**
     * Obtiene el certificado en formato PEM que tiene la llave pública
     * @return certificado 
     */
    public X509CertificateSeg getX509CertificateSeg()
    {
        return certificateSeg;
    } 
    
    /**
     * Escribe el certificado P12 en el Flujo de salida
     * @param outputStream es flujo de salida 
     * @throws CertificateEncodingException
     * @throws FileNotFoundException
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException 
     */
    public void writeToP12(OutputStream outputStream) throws CertificateEncodingException, FileNotFoundException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
    {
        //****************************  CARGAR LA LLAVE ***********************
        keyStore.store(outputStream,password.toCharArray());
        outputStream.flush();
        outputStream.close();
    }
    
    /**
     * Escribe el certificado en el archivo, si el archivo existe lo sobreescribe.
     * @param file Archivo donde se escribirá el certificado.
     * @throws KeyStoreException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException 
     */
    public void writeToP12(File file) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException
    {
        writeToP12(new FileOutputStream(file));
    }
    
    /**
     * Escribe el certificado en la URL 
     * @param pathP12 es la ruta URL
     * @throws KeyStoreException
     * @throws FileNotFoundException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException 
     */
    public void writeToP12(String pathP12) throws KeyStoreException, FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException
    {
        writeToP12(new FileOutputStream(pathP12));
    }
    
    /**
     * Firma un documento contenido en el dataStream y escribe el documento firmado en el outputStream
     * @param dataStream es el documento a ser firmado
     * @param outputStream  es el documento firmado
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException 
     */
    public void sign(DataStream dataStream,OutputStream outputStream) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException
    {
        Signature signature = Signature.getInstance(Properties.ENCODER_NAME);
        signature.initSign(privateKey);
        signature.update(dataStream.getData());
        byte[] data = signature.sign();
        outputStream.write(data);
        outputStream.flush();
        outputStream.close();
    }
    
    /**
     * Firma un documento contenido en el dataStream y escribe el documento firmado en la URL
     * @param dataStream es el documento a ser firmado
     * @param pathOutput es la URL del documento firmado
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException 
     */
    public void sign(DataStream dataStream,String pathOutput) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException
    {
        sign(dataStream, new FileOutputStream(pathOutput));
    }

    /**
     * Obtiene una representación en cadena del certificado
     * @return un String
     */
    @Override
    public String toString()
    {
        return "P12CertificateSeg{" + "privateKey=" + privateKey + ", certificateSeg=" + certificateSeg + ", keyStore=" + keyStore + ", password=" + password + '}';
    }
}