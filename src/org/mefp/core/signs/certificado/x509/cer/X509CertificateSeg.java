package org.mefp.core.signs.certificado.x509.cer;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.math.BigDecimal;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.bouncycastle.util.encoders.Base64;
import org.mefp.core.signs.certificado.util.Properties;
import org.mefp.core.signs.certificado.util.DataStream;
import org.mefp.core.signs.certificado.x509.data.Issuer;
import org.mefp.core.signs.certificado.x509.data.Subject;

/**
 * @author rcoarite
 */
public class X509CertificateSeg
{
    static
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    
    /**
     * El emisor del cerficado
     */
    private Issuer issuer;
    /**
     * El suscriptor
     */
    private Subject subject;
    /**
     * El certificado
     */
    private X509Certificate x509Certificate;
    
    private X509CertificateSeg(){}
    
    /**
     * Carga el certificado a partir de un DataStream
     * @param dataStream El Flujo de Entrada que representa al certificado en formato p12
     * @return El objeto Certificado
     * @throws CertificateException
     * @throws IOException 
     */
    public static X509CertificateSeg load(DataStream dataStream) throws CertificateException, IOException
    {
        X509CertificateSeg certificateSeg = new X509CertificateSeg();
        certificateSeg.x509Certificate = parseCertificatePem(dataStream.getData());
        certificateSeg.loadAttributesFromCertificate();
        return certificateSeg;
    }
    
    /**
     * Carga el certificado a partir de la referencia de un certificado 
     * @param certificate El X509CertificateSeg 
     * @return  El objeto certificado
     */
    public static X509CertificateSeg load(Certificate certificate)
    {
        if(!(certificate instanceof X509Certificate))
            throw new RuntimeException("El certificado no esta en le formato X509Certificate");
        X509CertificateSeg certificateSeg = new X509CertificateSeg();
        certificateSeg.x509Certificate = (X509Certificate)certificate;
        certificateSeg.loadAttributesFromCertificate();
        return certificateSeg;
    }
    
    /**
     * Crea una nueva instancia del X509CertificadoSeg con el emisor y suscriptor
     * @param x509Certificate El certificado en formato X509Certificate
     * @param issuer El emisor
     * @param subject El Suscriptor
     * @return  El Objeto X509CertificateSeg
     */
    public static X509CertificateSeg newInstance(X509Certificate x509Certificate,Issuer issuer,Subject subject)
    {
        X509CertificateSeg x509 = new X509CertificateSeg();
        x509.issuer = issuer;
        x509.subject = subject;
        x509.x509Certificate = x509Certificate;
        return x509;
    }
    
    /**
     * obtiene atributos de Issuer y subject a partir de su DN name
     */
    private void loadAttributesFromCertificate()
    {              
       //issuer
        String dd = x509Certificate.getIssuerDN().getName();       
        String CN = getValByAttributeTypeFromIssuerDN(dd,"CN=");
        String C = getValByAttributeTypeFromIssuerDN(dd,"C=");
        String O = getValByAttributeTypeFromIssuerDN(dd,"O=");               
        issuer = new Issuer();
        issuer.setName(CN);
        issuer.setCountry(C);
        issuer.setSocialReason(O);
        
        //subject
        String su = x509Certificate.getSubjectDN().getName();      
        String CNs = getValByAttributeTypeFromIssuerDN(su,"CN=");
        String Cs = getValByAttributeTypeFromIssuerDN(su,"C=");
        String Os = getValByAttributeTypeFromIssuerDN(su,"O=");
        String Sn = getValByAttributeTypeFromIssuerDN(su,"SERIALNUMBER=");
        String E = getValByAttributeTypeFromIssuerDN(su,"EMAILADDRESS=");               
        subject = new Subject();
        subject.setName(CNs);
        subject.setCountry(Cs);
        subject.setSerialNumber(new BigDecimal (Sn));
        subject.setEmail(E);
    }
    
    /**
     * Obtiene un dato del DN de acuerdo al attributeType
     * @param dn es el Distinct Name del Emisor y Subscriptor 
     * @param attributeType
     * @return 
     */
    private String getValByAttributeTypeFromIssuerDN(String dn, String attributeType)
    {
        String[] dnSplits = dn.split(","); 
        for (String dnSplit : dnSplits)
        {
            if (dnSplit.contains(attributeType))
            {
                String[] cnSplits = dnSplit.trim().split("=");
                if(cnSplits.length==1)
                    return "";
                if(cnSplits[1]!= null)
                {
                    return cnSplits[1].trim();
                }
            }
        }
        return "";
    }
    
    /**
     * Parsea los bytes que son de un archivo PEM y lo convierte a X509Certificate
     * @param bytes Los bytes del archivo PEM
     * @return El X509Certifcate
     * @throws CertificateException
     * @throws FileNotFoundException
     * @throws IOException 
     */
    private static X509Certificate parseCertificatePem(byte[] bytes) throws CertificateException, FileNotFoundException, IOException
    {
        String certStr = new String(bytes);
        byte [] decoded = Base64.decode(certStr.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", ""));
        //String certStr = _request.getHeader("x-clientcert");
        return (X509Certificate)CertificateFactory.getInstance(Properties.CERTIFICATE_TYPE).generateCertificate(new ByteArrayInputStream(decoded));
    }

    /**
     * Obtiene certificado con la llave pública
     * @return certificado con la llave pública
     */
    public X509Certificate getX509Certificate()
    {
        return x509Certificate;
    }

    /**
     * Obtiene la llave pública
     * @return La llave pública del certificado X509
     */
    public PublicKey getPublicKey() {
        return x509Certificate.getPublicKey();
    }

    /**
     * Obtiene el emisor
     * @return Emisor
     */
    public Issuer getIssuer() {
        return issuer;
    }

    /**
     * Obtiene el Suscriptor
     * @return Suscriptor
     */
    public Subject getSubject() {
        return subject;
    }
    
    /**
     * Escribe en un archivo el certificado en formato PEM
     * @param path La ruta donde se almacenará el certificado
     * @throws CertificateEncodingException
     * @throws FileNotFoundException 
     */
    public void writeToPem(String path) throws CertificateEncodingException, FileNotFoundException
    {
        writeToPem(new FileOutputStream(path));
    }
    
    /**
     * Genera un certificado con formato PEM
     * @param outputStream flujo de salida
     * @throws CertificateEncodingException 
     */
    public void writeToPem(OutputStream outputStream) throws CertificateEncodingException
    {
        String cert_begin = "-----BEGIN CERTIFICATE-----\n";
        String end_cert = "-----END CERTIFICATE-----";

        byte[] derCert = x509Certificate.getEncoded();
        String pemCertPre = new String(Base64.encode(derCert));
        String pemCert = cert_begin + pemCertPre + end_cert;
        PrintWriter printWriter = new PrintWriter(outputStream);
        printWriter.write(pemCert);
        printWriter.close();
    }
    
    /**
     * Verfica si el archivo original a sufrido cambios. La verificación se hace con el archivo firmado (.sig)
     * El método utiliza el llave pública para realizar la verificación
     * @param dataSource El archivo original a verificar
     * @param dataEvenpoye El archivo firmado
     * @return TRUE si el archivo no ha sufrido cambios y FALSE por lo contrario
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException 
     */
    public boolean verify(DataStream dataSource,DataStream dataEvenpoye) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
        Signature sig = Signature.getInstance(Properties.ENCODER_NAME);
        sig.initVerify(x509Certificate.getPublicKey());
        sig.update(dataSource.getData());
        return sig.verify(dataEvenpoye.getData());
    }
    
    /**
     * Verifica si el certificado esta autofirmado
     * @return TRUE si el certificado esta auto frimado
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException 
     */
    public boolean isSelfSigned() throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException
    {
        return verify(getPublicKey());
    }
    
    /**
     * Verifica si el certificado es firmado con la llave publica como parametro
     * @param publicKey La llave publica del certificado emisor
     * @return TRUE si esta firmado con la entidad con la llave publica
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException 
     */
    public boolean verify(PublicKey publicKey) throws CertificateException, NoSuchAlgorithmException, NoSuchProviderException
    {
        try
        {
            // Trata de verificar la firma del certificado con su propia clave pública
            x509Certificate.verify(publicKey,Properties.BOUNCY_CASTLE_NAME_PROVIDER);
            return true;
        }
        catch (SignatureException sigEx)
        {
            // Firma no válida -> no autofirmado
            return false;
        }
        catch (InvalidKeyException keyEx)
        {
            // Firma no válida -> no autofirmado
            return false;
        }
    }

    /**
     * Obtiene una representación en cadena del certificado
     * @return un objeto de tipo certificado
     */
    @Override
    public String toString()
    {
        StringBuilder certificateInfo = new StringBuilder();
        certificateInfo.append("Nº serie: [").append(x509Certificate.getSerialNumber()).append("] ").append("\n");
        certificateInfo.append("Fecha caducidad: [").append(x509Certificate.getNotAfter()).append("]\n");
        certificateInfo.append(issuer).append("\n");
        certificateInfo.append(subject).append("\n");
        return certificateInfo.toString();
    }
}