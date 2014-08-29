package org.mefp.core.signs.certificado.x509;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.mefp.core.signs.certificado.x509.data.Issuer;
import org.mefp.core.signs.certificado.x509.data.Subject;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.mefp.core.signs.certificado.util.Properties;
import org.mefp.core.signs.certificado.x509.cer.P12CertificateSeg;
import org.mefp.core.signs.certificado.x509.cer.X509CertificateSeg;

/**
 * La mayoría del código presente se toma de la siguiente página
 * https://wiki.csiro.au/pages/viewpage.action?pageId=611616449
 * Clase utilitara para crear firmas .p12 o .pem con llave privada o solo llave publica
 * 
 * @author rcoarite
 */
public class CertificateBuilder
{
    static
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    /**
     * Genera un par de llaves privada y pública con el Algoritmo RSA y el tamaño de la firma
     * especificado en KEY_SIZE
     * @return El par de llaves 
     * @throws NoSuchAlgorithmException En caso de no encontrar el algoritmo RSA
     */
    public static KeyPair generateKeypair() throws NoSuchAlgorithmException
    {
        KeyPairGenerator keygenerator;
        keygenerator = KeyPairGenerator.getInstance("RSA");
        keygenerator.initialize(Properties.KEY_SIZE);
        KeyPair keypair = keygenerator.generateKeyPair();
        return keypair;
    }
     
    /**
     * Crea una instancia de X509CertificateSeg 
     * @param privateKey La llave privada de la autoridad certificadora
     * @param publicKey La llave pública de la entidad
     * @param issuer El emisor del certificado
     * @param subject EL suscriptor o la entidad
     * @param validityDays El número de días válido del certificado
     * @param keyUsage El modo de uso de la firma.\n
     * La formas de uso pueden ser:\n
     * KeyUsage.digitalSignature = Firmado de documentos\n
     * KeyUsage.keyEncipherment = Encriptado de correo electronico y documentos (archivos)\n
     * KeyUsage.keyCertSign = Creacion de certificados\n
     * @return Un X509CertificateSeg con llave privada y pública
     * @throws OperatorCreationException
     * @throws CertificateException 
     * @throws java.security.InvalidKeyException 
     * @see org.bouncycastle.asn1.x509.KeyUsage
     */
    public static X509CertificateSeg generateCertificate(
            PrivateKey privateKey,
            PublicKey publicKey,
            Issuer issuer, 
            Subject subject,
            int validityDays,
            int keyUsage)
            throws OperatorCreationException, CertificateException, InvalidKeyException
    {
        Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.DAY_OF_YEAR, validityDays);
        //certGen.setEndDate(new Time(expiry.getTime()));
        //certGen.setStartDate(new Time(new Date(System.currentTimeMillis())));
        
        X509Certificate cert;
        Date startDate = new Date(System.currentTimeMillis());
        Date endDate = expiry.getTime();
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        
        X500NameBuilder builderIssuer = new X500NameBuilder(BCStyle.INSTANCE);
        if(issuer.getName() == null)
            throw new RuntimeException("El nombre del emisor es nulo");
        builderIssuer.addRDN(BCStyle.CN, issuer.getName());
        builderIssuer.addRDN(BCStyle.O, issuer.getSocialReason());
        builderIssuer.addRDN(BCStyle.C,issuer.getCountry());

        X500NameBuilder builderSubject = new X500NameBuilder(BCStyle.INSTANCE);
        builderSubject.addRDN(BCStyle.CN,subject.getName());
        builderSubject.addRDN(BCStyle.C, subject.getCountry());
        builderSubject.addRDN(BCStyle.SN,subject.getSerialNumber().toPlainString());
        builderSubject.addRDN(BCStyle.E, subject.getEmail());        

        ContentSigner sigGen = new JcaContentSignerBuilder(Properties.ENCODER_NAME)
                .setProvider(Properties.BOUNCY_CASTLE_NAME_PROVIDER).build(privateKey);
        // Creando certificado con la version 3
        X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                builderIssuer.build(),
                serial, // EL numero de serie del certificado
                startDate, // Fecha de inicio del certificado
                endDate, // Fecha de expiracion del certificado
                builderSubject.build(),
                publicKey); // La llave publica de la entidad a ser creada su firma

        
        certGen.addExtension(org.bouncycastle.asn1.x509.X509Extension.basicConstraints, false, new BasicConstraints(false));
        // Estableciendo que la firma solo puede firmar y encriptar. El portador de la firma no podra crer otras firmas a partir de ella
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(keyUsage));
        // KeyUsage.keyCertSign asigna permisos de firmado

        cert = new JcaX509CertificateConverter().setProvider(Properties.BOUNCY_CASTLE_NAME_PROVIDER)
                .getCertificate(certGen.build(sigGen));
        return X509CertificateSeg.newInstance(cert, issuer, subject);
    }
    
    /**
     * Genera un certificado P12CertificadeSeg
     * @param privateKey La llave privada del firmante
     * @param x509CertificateSeg El Certificado con la llave pública
     * @param password La contraseña con la que se generará el certificado p12
     * @return un objeto de tipo certificado en formato P12
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException 
     */
    public static P12CertificateSeg generateP12Certificate(PrivateKey privateKey,X509CertificateSeg x509CertificateSeg,String password) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException
    {
        //Certificate[] outChain = { createCertificate("CN=Client", "CN=CA", publicKey, privateKey), trustCert };
        Certificate[] outChain = {x509CertificateSeg.getX509Certificate()};

        KeyStore outStore = KeyStore.getInstance("PKCS12");
        outStore.load(null,password.toCharArray());
        outStore.setKeyEntry(Properties.ALIAS_KEY, privateKey,password.toCharArray(), outChain);
        
        P12CertificateSeg certificateSeg = P12CertificateSeg.newInstance(outStore, x509CertificateSeg, privateKey,password);
        return certificateSeg;
    }
}