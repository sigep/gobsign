package pruebas_firmado;

import java.io.File;
import java.io.FileInputStream;
import org.sigep.core.signs.certificado.util.DataStream;
import org.sigep.core.signs.certificado.x509.cer.P12CertificateSeg;
import org.sigep.core.signs.certificado.x509.cer.X509CertificateSeg;
import pruebas_certificados.RutasCertificados;
import static pruebas_certificados.RutasCertificados.DOCUMENTO_FIRMADO;
import static pruebas_certificados.RutasCertificados.DOCUMENTO_PARA_FIRMAR;

/**
 *
 * @author rcoarite
 */
public class Paso1_FirmarUnDocumentoPorEntidad implements RutasCertificados
{
    public static void main(String cor[]) throws Exception
    {
        // Cargamos el certificado de la entidad
        P12CertificateSeg certificateLoaded = P12CertificateSeg.load(
                new FileInputStream(RUTA_CERTIFICADO_PRIVADO_ENTIDAD),
                CLAVE_DE_CERTIFICADO_PRIVADO);
        // Firmamos el documeto
        certificateLoaded.sign(DataStream.load(new File(DOCUMENTO_PARA_FIRMAR)), DOCUMENTO_FIRMADO);
        
        X509CertificateSeg x509Certificate = certificateLoaded.getX509CertificateSeg();
        
        // Verificamos el documento firmado
        boolean esCorrecto = x509Certificate.verify(DataStream.load(new File(DOCUMENTO_PARA_FIRMAR)),DataStream.load(new File(DOCUMENTO_FIRMADO)));
        if(esCorrecto)
            System.out.println("Si esta correcto y firmado por la entidad");
        else
            System.err.println("NO esta correcto");
    }
}