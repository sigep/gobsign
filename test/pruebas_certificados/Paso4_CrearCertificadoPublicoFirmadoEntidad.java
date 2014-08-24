package pruebas_certificados;

import java.io.FileInputStream;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.sigep.core.signs.certificado.x509.CertificateBuilder;
import org.sigep.core.signs.certificado.x509.cer.P12CertificateSeg;
import org.sigep.core.signs.certificado.x509.cer.X509CertificateSeg;

/**
 *
 * @author rcoarite
 */
public class Paso4_CrearCertificadoPublicoFirmadoEntidad implements RutasCertificados
{
    public static void main(String cor[]) throws Exception
    {
        // Cargamos el certificado privado raiz
        P12CertificateSeg certificateRaiz = P12CertificateSeg.load(new FileInputStream(RUTA_CERTIFICADO_PRIVADO_RAIZ),CLAVE_DE_CERTIFICADO_PRIVADO);
        
        // Cargamos el certificado privado entidad
        P12CertificateSeg certificateEntidad = P12CertificateSeg.load(new FileInputStream(RUTA_CERTIFICADO_PRIVADO_ENTIDAD),CLAVE_DE_CERTIFICADO_PRIVADO);
        
        // Obtenemos el certificado publico de la entidad
        X509CertificateSeg x509CertificateEntidad = certificateEntidad.getX509CertificateSeg();
        X509CertificateSeg x509CertificateEntidadFirmado = CertificateBuilder.generateCertificate(
                certificateRaiz.getPrivateKey(),
                x509CertificateEntidad.getPublicKey(),
                x509CertificateEntidad.getIssuer(),
                x509CertificateEntidad.getSubject(),
                365,
                KeyUsage.keyEncipherment|KeyUsage.keyCertSign|KeyUsage.digitalSignature);
        x509CertificateEntidadFirmado.writeToPem(RUTA_CERTIFICADO_PUBLICO_ENTIDAD);
        
        // Actualizamo el certificado privado de la entidad con el certificado publico firmado
        certificateEntidad = CertificateBuilder.generateP12Certificate(
                certificateEntidad.getPrivateKey(),
                x509CertificateEntidadFirmado,
                CLAVE_DE_CERTIFICADO_PRIVADO);
        certificateEntidad.writeToP12(RUTA_CERTIFICADO_PRIVADO_ENTIDAD);
    }
}