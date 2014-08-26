package pruebas_firmado;

import java.io.File;
import org.sigep.core.signs.certificado.util.DataStream;
import org.sigep.core.signs.certificado.x509.cer.X509CertificateSeg;
import pruebas_certificados.RutasCertificados;

/**
 *
 * @author rcoarite
 */
public class Paso3_VerificarFirmadoPorEntidad implements RutasCertificados
{
    public static void main(String cor[]) throws Exception
    {
        // Cargamos el certificado publico de la entidad que lo firmo
        X509CertificateSeg x509Certificate = X509CertificateSeg.load(DataStream.load(new File(RUTA_CERTIFICADO_PUBLICO_ENTIDAD)));
        X509CertificateSeg x509Certificateraiz = X509CertificateSeg.load(DataStream.load(new File(RUTA_CERTIFICADO_PUBLICO_RAIZ)));
        
        // Verificamos el documento firmado
        boolean esCorrecto = x509Certificate.verify(DataStream.load(new File(DOCUMENTO_PARA_FIRMAR)),DataStream.load(new File(DOCUMENTO_FIRMADO)));
        if(esCorrecto)
            System.out.println("Si esta correcto y firmado por la entidad");
        else
            System.err.println("NO esta correcto");
        boolean esValido = x509Certificate.verify(x509Certificateraiz.getPublicKey());
        if(esValido)
            System.out.println("Si esta valido y esta firmado por la autoridad certificante");
        else
            System.err.println("No es valido");
        
    }
}