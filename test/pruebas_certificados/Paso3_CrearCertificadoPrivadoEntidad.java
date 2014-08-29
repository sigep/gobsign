package pruebas_certificados;

import java.security.KeyPair;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.mefp.core.signs.certificado.x509.CertificateBuilder;
import org.mefp.core.signs.certificado.x509.cer.P12CertificateSeg;
import org.mefp.core.signs.certificado.x509.cer.X509CertificateSeg;
import org.mefp.core.signs.certificado.x509.data.Issuer;
import org.mefp.core.signs.certificado.x509.data.Subject;
import static pruebas_certificados.RutasCertificados.CLAVE_DE_CERTIFICADO_PRIVADO;

/**
 *
 * @author rcoarite
 */
public class Paso3_CrearCertificadoPrivadoEntidad implements RutasCertificados
{
    public static void main(String cor[]) throws Exception
    {
        // Crea un par de llaves para el certificado de la entidad
        KeyPair keyPair = CertificateBuilder.generateKeypair();
        
        // Creamos el certificado publico
        Issuer issuer = new Issuer();
        issuer.setName("DGSGIF");
        issuer.setSocialReason("Direccion General de Sistemas");
        
        Subject subject = new Subject();
        subject.setCountry("Bolivia");
        subject.setEmail("dpt@dual.com");
        subject.setSerialNumber(23456786543245678L);
        subject.setName("Rigochito");
        
        X509CertificateSeg certificateSeg = CertificateBuilder.generateCertificate(
                keyPair.getPrivate(),
                keyPair.getPublic(),
                issuer,
                subject,
                365,
                KeyUsage.keyEncipherment|KeyUsage.keyCertSign|KeyUsage.digitalSignature);
        
        P12CertificateSeg certificateP12Seg = CertificateBuilder.generateP12Certificate(
                keyPair.getPrivate(), certificateSeg,CLAVE_DE_CERTIFICADO_PRIVADO);
        System.out.println(certificateP12Seg);
        
        // Guardando el certificado
        certificateP12Seg.writeToP12(RUTA_CERTIFICADO_PRIVADO_ENTIDAD);
    }
}