package prueba;

import java.security.Security;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.sigep.core.signs.certificado.x509.CertificateBuilder;
import org.sigep.core.signs.certificado.x509.cer.P12CertificateSeg;
import org.sigep.core.signs.certificado.x509.cer.X509CertificateSeg;
import org.sigep.core.signs.certificado.x509.data.Issuer;
import org.sigep.core.signs.certificado.x509.data.Subject;

/**
 * Crea un certificado a partir de otra. Es necesario que el certificado tenga asignado
 * los premios de generación de firmas y firmado
 * @author rcoarite
 */
public class CrearCertificadoFirmadoPorOtra
{
    public static void main(String cor[]) throws Exception
    {
         Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        
        // Cargando certificado 
        String ruta_certificado = "c:\\llaves\\certificadoprivadoministerio.p12";
        String clave_certificado = "dgsgif";
        
        // Cargando certificado raiz
        P12CertificateSeg certificateP12 = P12CertificateSeg.load(ruta_certificado,clave_certificado);
        
        // Creando un nuevo certificado autofirmado
        Issuer issuer = new Issuer();
        issuer.setName("HAMRAP");
        issuer.setSocialReason("ministerio de ecomomia");
        Subject subject = new Subject();
        subject.setName("dilma yugar");
        subject.setCountry("Bolivia");
        subject.setSerialNumber(12345678976543L);
        subject.setEmail("laesquina@dylma.com");
        X509CertificateSeg certificateSeg = CertificateBuilder.generateCertificate(
                certificateP12.getPrivateKey(),
                CertificateBuilder.generateKeypair().getPublic(),
                issuer,
                subject,
                365,
                KeyUsage.keyEncipherment|KeyUsage.keyCertSign|KeyUsage.digitalSignature);
        P12CertificateSeg newCertificateSeg = CertificateBuilder.generateP12Certificate(certificateP12.getPrivateKey(), certificateSeg, clave_certificado);
        newCertificateSeg.writeToP12("c:\\llaves\\certificadoprivadodylma.p12");
        X509CertificateSeg x509CertificateSeg = newCertificateSeg.getX509CertificateSeg();
        x509CertificateSeg.writeToPem("c:\\llaves\\certificadopublicodilma.cer");
        
    }
}