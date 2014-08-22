package prueba;

import java.io.FileInputStream;
import java.security.KeyPair;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.sigep.core.signs.certificado.x509.CertificateBuilder;
import org.sigep.core.signs.certificado.x509.cer.P12CertificateSeg;
import org.sigep.core.signs.certificado.x509.cer.X509CertificateSeg;
import org.sigep.core.signs.certificado.x509.data.Issuer;
import org.sigep.core.signs.certificado.x509.data.Subject;

/**
 * Clase de prueba para generar certificados PEM
 * con llave pública autofirmado
 * El ejemplo Genera una llave y lo vuelve a cargar
 * @author rcoarite
 */
public class PruebaGeneracionP12
{
    public static void main(String a[]) throws Exception
    {
        KeyPair keyPair = CertificateBuilder.generateKeypair();
        
        Issuer issuer = new Issuer();
        issuer.setName("DGSGIF");
        issuer.setSocialReason("Ministerio de Economia y Finanzas Publicas");
        
        Subject subject = new Subject();
        subject.setCountry("Bolivia");
        subject.setEmail("porcion@joaquin.com");
        subject.setSerialNumber(23456786543245678L);
        subject.setName("joaquin heredia molina");
        
        // Generando certificado PEM
        int validesEnDias = 30;
        X509CertificateSeg certificateSeg = CertificateBuilder.generateCertificate(
                keyPair.getPrivate(),
                keyPair.getPublic(),
                issuer, 
                subject,
                validesEnDias,
                KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
        
        String password = "dgsgif";
        P12CertificateSeg certificateP12Seg = CertificateBuilder.generateP12Certificate(keyPair.getPrivate(), certificateSeg, password);
        System.out.println(certificateP12Seg);
        
        // Guardando el certificado
        String ruta_certificado = "c:\\llaves\\certificadoprivadoministerio.p12";
        certificateP12Seg.writeToP12(ruta_certificado);
        
        // Leyendo el archivo generado
        P12CertificateSeg certificateLoaded = P12CertificateSeg.load(new FileInputStream(ruta_certificado),password);
        X509CertificateSeg x509CertificateSeg = certificateLoaded.getX509CertificateSeg();
        x509CertificateSeg.writeToPem("c:\\llaves\\certificadopublicoministerio.pem");
        // Mostrando datos de la carga del certificado
        System.out.println();
        System.out.println(certificateLoaded);
    }
}