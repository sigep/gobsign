package prueba;

import java.io.File;
import org.sigep.core.signs.certificado.util.DataStream;
import org.sigep.core.signs.certificado.x509.cer.X509CertificateSeg;

/**
 *
 * @author rcoarite
 */
public class VerficarCertificadoAutoFirmado
{
    public static void main(String cor[]) throws Exception
    {
        String ruta_certificado = "E:\\llaves\\certificado_pem.pem";
        
        // Leyendo el archivo PEM
        X509CertificateSeg certificateSegReaded = X509CertificateSeg.load(DataStream.load(new File(ruta_certificado)));
        System.out.println(certificateSegReaded);
        
        // Verificamos si el certificado esta autofirmado
        if(certificateSegReaded.isSelfSigned())
        {
            System.out.println("El certificado esta auto firmado o firmado por si misma");
        }
        else
        {
            System.out.println("El certificado esta correctamente firmado o es valido");
        }
    }
}
