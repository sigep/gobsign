package prueba;

import com.lowagie.text.pdf.PdfReader;
import java.io.FileOutputStream;
import java.security.Provider;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.sigep.core.signs.certificado.util.PdfSigner;
import org.sigep.core.signs.certificado.x509.cer.P12CertificateSeg;

/**
 * Clase de prueba para verificar y firmar documentos PDF a partir de un certificado .p12
 * @author Ronald Coarite
 */
public class Firma_y_Verificacion_PDF
{
    public static void main(String main[]) throws Exception
    {
        Provider provider=new BouncyCastleProvider();
        Security.addProvider(provider);
        
        String ruta_certificado = "E:\\llaves\\certificado_pcs12.p12";
        String ruta_archivo_pdf = "E:\\llaves\\documento_pdf.pdf";
        String ruta_archivo_pdf_firmado = "E:\\llaves\\documento_pdf_firmado.pdf";
        String clave_certificado = "dgsgif";
        
        // Cargando llave
        P12CertificateSeg certificateP12 = P12CertificateSeg.load(ruta_certificado,clave_certificado);
        
        // Creando documento firmado
        PdfSigner.signPDF(new PdfReader(ruta_archivo_pdf), new FileOutputStream(ruta_archivo_pdf_firmado), certificateP12);
        
        // Verficando el documento firmado
        String mensaje = PdfSigner.verifSign(new PdfReader(ruta_archivo_pdf_firmado));
        if(mensaje == null)
            System.out.println("La firma esta correcta");
        else
            System.out.println("Error: "+mensaje);
    }
}