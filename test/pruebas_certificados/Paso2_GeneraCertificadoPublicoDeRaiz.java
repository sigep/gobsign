package pruebas_certificados;

import java.io.FileInputStream;
import org.sigep.core.signs.certificado.x509.cer.P12CertificateSeg;
import org.sigep.core.signs.certificado.x509.cer.X509CertificateSeg;

/**
 *
 * @author rcoarite
 */
public class Paso2_GeneraCertificadoPublicoDeRaiz implements RutasCertificados
{
    public static void main(String cor[]) throws Exception
    {
        P12CertificateSeg certificateLoaded = P12CertificateSeg.load(new FileInputStream(RUTA_CERTIFICADO_PRIVADO_RAIZ),CLAVE_DE_CERTIFICADO_PRIVADO);
        X509CertificateSeg certificateSeg = certificateLoaded.getX509CertificateSeg();
        certificateSeg.writeToPem(RUTA_CERTIFICADO_PUBLICO_RAIZ);
    }
}