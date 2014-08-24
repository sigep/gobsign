package pruebas_certificados;

import java.io.File;
import org.sigep.core.signs.certificado.util.DataStream;
import org.sigep.core.signs.certificado.x509.cer.X509CertificateSeg;

/**
 *
 * @author rcoarite
 */
public class Paso5_VerficacionDeAutoFirmadoCertPubEntidad implements RutasCertificados
{
    public static void main(String cor[]) throws Exception
    {
        // Cargamos el certificado publico de la raiz
        X509CertificateSeg x509CertificateRaiz = X509CertificateSeg.load(DataStream.load(new File(RUTA_CERTIFICADO_PUBLICO_RAIZ)));
        
        // Cargamos el certificado publico de la entidad
        X509CertificateSeg x509CertificateEntidad = X509CertificateSeg.load(DataStream.load(new File(RUTA_CERTIFICADO_PUBLICO_ENTIDAD)));
        
        // Verificamos si esta autofirmado por la entidad misma
        if(x509CertificateEntidad.isSelfSigned())
            System.out.println("Si esta auto FIRMADO");
        else
            System.out.println("NO esta autofirmado");       
        
        // Verficamos si esta firmado por la raiz
        if(x509CertificateEntidad.verify(x509CertificateRaiz.getPublicKey()))
            System.out.println("Si esta firmado por la entidad raiz");
        else
            System.out.println("NO esta firmado por la entidad");
    }
}