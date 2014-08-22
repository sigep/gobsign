package org.sigep.core.signs.certificado.util;

import com.lowagie.text.DocumentException;
import com.lowagie.text.pdf.AcroFields;
import com.lowagie.text.pdf.PdfPKCS7;
import com.lowagie.text.pdf.PdfReader;
import com.lowagie.text.pdf.PdfSigGenericPKCS;
import com.lowagie.text.pdf.PdfSignatureAppearance;
import com.lowagie.text.pdf.PdfStamper;
//import com.​lowagie.​text.Rectangle;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;
import org.sigep.core.signs.certificado.x509.cer.P12CertificateSeg;

/**
 * Clase utilitaria para realizar el firmado embebido de un documento PDF y
 * su correspondiente verificación.
 * @author rcoarite
 */
public final class PdfSigner
{
    /**
     * Realiza el firmado de documentos PDF. Utilizando la llave privada del certifcado
     * y la escribe en le flujo de salida del OutpuStream
     * @param pdfReader El PDFReader que representa al PDF
     * @param ouputSigned El flujo de salida del documento firmado
     * @param p12Certificate La referencia al certificado p12
     * @throws DocumentException
     * @throws IOException 
     */
    public static void signPDF(PdfReader pdfReader,OutputStream ouputSigned,P12CertificateSeg p12Certificate) throws DocumentException, IOException
    {
        // Añadimos firma al documento PDF
        PdfStamper stp = PdfStamper.createSignature(pdfReader, ouputSigned, '?');
        PdfSignatureAppearance sap = stp.getSignatureAppearance();
        sap.setCrypto(
                p12Certificate.getPrivateKey(),
                new Certificate[]{p12Certificate.getX509CertificateSeg().getX509Certificate()},
                null,PdfSignatureAppearance.SELF_SIGNED
                     //PdfSignatureAppearance.WINCER_SIGNED
                    );
        sap.setReason("Firma PKCS12");
        sap.setLocation("Imaginanet");
        sap.setSignDate(new GregorianCalendar());
        sap.setContact("This is the Contact");
        // Añade la firma visible. Podemos comentarla para que no sea visible.
        //sap.setVisibleSignature(new Rectangle(100,100,200,200),1,null);
        stp.close();
    }
    
    /**
     * Verifica si el documento esta correctamente firmado
     * @param pdfReader El objeto que hace referencia al documento PDF
     * @return Un String distinto de null en caso de encontrar algun error o que el documento haya sido modificado
     */
    public static final String verifSign(PdfReader pdfReader)
    {
        KeyStore kall = PdfPKCS7.loadCacertsKeyStore();
        AcroFields acroFields = pdfReader.getAcroFields();
        List<String> signatureNames = acroFields.getSignatureNames();
        if (signatureNames.isEmpty())
        {
            return ("El documento no tiene ni una firma registrada");
        }
        for(String name : signatureNames)
        {
            if (!acroFields.signatureCoversWholeDocument(name))
            {
                return ("la firma: "+name+" does not covers the whole document.");
            }
            PdfPKCS7 pk = acroFields.verifySignature(name);
            Certificate[] certificates = pk.getCertificates();
            Calendar cal = pk.getSignDate();
            //System.out.println("Document modified: " + !pk.verify());
            Object fails[] = PdfPKCS7.verifyCertificates(certificates, kall, null, cal);
            if (fails == null)
            {
                // Documento PDF firmado correctamente
            }
            else
            {
                return ("Firma no válida."+fails[0]+"\n"+fails[1]);
            }
        }
        // Todo firmado correctamente
        return null;
   }
}