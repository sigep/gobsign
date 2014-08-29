package pruebas_firmado;

import java.io.File;
import org.mefp.core.signs.certificado.util.DataStream;
import org.mefp.core.signs.certificado.x509.cer.X509CertificateSeg;
import pruebas_certificados.RutasCertificados;

/**
 *
 * @author rcoarite
 */
public class Paso2_VerificarFirmadoPorRaiz implements RutasCertificados
{
    public static void main(String cor[]) throws Exception
    {
        // Cargamos el certificado publico de la entidad que lo firmo
        X509CertificateSeg x509Certificate = X509CertificateSeg.load(DataStream.load(new File(RUTA_CERTIFICADO_PUBLICO_RAIZ)));
        
        // Verificamos el documento firmado
        boolean esCorrecto = x509Certificate.verify(DataStream.load(new File(DOCUMENTO_PARA_FIRMAR)),DataStream.load(new File(DOCUMENTO_FIRMADO)));
        if(esCorrecto)
            System.out.println("Si esta correcto y firmado por la entidad");
        else
            System.err.println("NO esta correcto");
    }
}