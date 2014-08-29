package pruebas_certificados;

import java.security.KeyPair;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.mefp.core.signs.certificado.x509.CertificateBuilder;
import org.mefp.core.signs.certificado.x509.cer.P12CertificateSeg;
import org.mefp.core.signs.certificado.x509.cer.X509CertificateSeg;
import org.mefp.core.signs.certificado.x509.data.Issuer;
import org.mefp.core.signs.certificado.x509.data.Subject;

/**
 *
 * @author rcoarite
 */
public class Paso1_CrearCertificadoRaiz implements RutasCertificados
{
    public static void main(String cor[]) throws Exception
    {
        KeyPair keyPair = CertificateBuilder.generateKeypair();
        
        Issuer issuer = new Issuer();
        issuer.setName("MEEP");
        issuer.setSocialReason("Ministerio de economia y Finanzas Publicas");
        
        Subject subject = new Subject();
        subject.setCountry("Bolivia");
        subject.setEmail("porcion@donpollo.com");
        subject.setSerialNumber(23456786543245678L);
        subject.setName("Roberto Linares Luco");
        
        // Generando certificado PEM
        int validesEnDias = 30;
        X509CertificateSeg certificateSeg = CertificateBuilder.generateCertificate(
                keyPair.getPrivate(),
                keyPair.getPublic(),
                issuer, 
                subject,
                validesEnDias,
                KeyUsage.keyEncipherment|KeyUsage.keyCertSign|KeyUsage.digitalSignature);
        
        P12CertificateSeg certificateP12Seg = CertificateBuilder.generateP12Certificate(
                keyPair.getPrivate(), certificateSeg,CLAVE_DE_CERTIFICADO_PRIVADO);
        System.out.println(certificateP12Seg);
        
        // Guardando el certificado
        certificateP12Seg.writeToP12(RUTA_CERTIFICADO_PRIVADO_RAIZ);
    }
}