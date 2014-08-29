package prueba;

import java.io.File;
import java.security.KeyPair;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.mefp.core.signs.certificado.util.DataStream;
import org.mefp.core.signs.certificado.x509.CertificateBuilder;
import org.mefp.core.signs.certificado.x509.cer.X509CertificateSeg;
import org.mefp.core.signs.certificado.x509.data.Issuer;
import org.mefp.core.signs.certificado.x509.data.Subject;

/**
 * Clase de prueba para generar certificados PEM
 * con llave pública
 * El ejemplo Genera una llave y lo vuelve a cargar
 * @author rcoarite
 */
public class PruebaGeneracionPEM
{
    public static void main(String a[]) throws Exception
    {
        KeyPair keyPair = CertificateBuilder.generateKeypair();
        
        Issuer issuer = new Issuer();
        issuer.setName("DGSGIF");
        issuer.setSocialReason("Ministerio de Economia y Finanzas Publicas");
        
        
        Subject subject = new Subject();
        subject.setCountry("Bolivia");
        subject.setEmail("porcion@donpollo.com");
        subject.setSerialNumber(23456786543245678L);
        subject.setName("Roberto Linares Luco");
        
        // Generando certificado
        int validesEnDias = 30;
        // Generamos una firma autofirmada
        X509CertificateSeg certificateSeg = CertificateBuilder.generateCertificate(
                keyPair.getPrivate(),
                keyPair.getPublic(),
                issuer,
                subject,
                validesEnDias,
                KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        System.out.println(certificateSeg);
        
        // Almacenando en formato PEM
        String ruta_certificado = "c:\\llaves\\certificado_pem.pem";
        certificateSeg.writeToPem(ruta_certificado);
        
        // Leyendo el archivo PEM
        System.out.println("");
        X509CertificateSeg certificateSegReaded = X509CertificateSeg.load(DataStream.load(new File(ruta_certificado)));
        System.out.println(certificateSegReaded);
    }
}