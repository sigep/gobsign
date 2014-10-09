
package org.mefp.core.signs.xml;
import java.io.File;  
import java.io.FileInputStream;  
import java.io.InputStream;
import java.security.KeyStore;  
import java.security.PrivateKey;  
import java.security.cert.X509Certificate; 
import org.apache.commons.io.IOUtils;
import javax.xml.parsers.DocumentBuilderFactory; 
  
import org.w3c.dom.*;  
import org.apache.xml.security.signature.XMLSignature;  
import org.apache.xml.security.transforms.Transforms;  
import org.apache.xml.security.utils.Constants; 

/**
 *Se tomó como referencia para el código la siguiente pagina:
 * http://www.adictosaltrabajo.com/tutoriales/tutoriales.php?pagina=xmlSignature
 * @author dyugar
 */
public class CreateSignature {
   
    private static final String KEYSTORE_TYPE         = "JKS";  
    private static final String KEYSTORE_FILE         = "E:\\herramientas\\myKeyStore1.jks";  
    private static final String KEYSTORE_PASSWORD     = "abc12345";  
    private static final String PRIVATE_KEY_PASSWORD  = "abc1234";  
    private static final String PRIVATE_KEY_ALIAS     = "mi_cert_ejemplo";  
    
    /** 
     * Punto de entrada al ejemplo 
     */  
    public static void main(String args[]) throws Exception {  
        org.apache.xml.security.Init.init();  
  
        //Document doc = DomUtils.createSampleDocument(); 
        
        //Documento a firmar
        final InputStream xmlFile= new FileInputStream("E:\\herramientas\\pruebaxml.xml");
        final Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(xmlFile);        
          
       //Constants.setSignatureSpecNSprefix(""); // Sino, pone por defecto como prefijo: "ns"   
  
        // Cargamos el almacen de claves  
        KeyStore ks  = KeyStore.getInstance(KEYSTORE_TYPE);  
        ks.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PASSWORD.toCharArray());  
  
        // Obtenemos la clave privada, pues la necesitaremos para encriptar.  
        PrivateKey privateKey = (PrivateKey) ks.getKey(PRIVATE_KEY_ALIAS, PRIVATE_KEY_PASSWORD.toCharArray());  
        File    signatureFile = new File("E:\\herramientas\\signaturexml.xml");        
        String  baseURI       = signatureFile.toURL().toString();   // BaseURI para las URL Relativas.  
                 
        // Instanciamos un objeto XMLSignature desde el Document. El algoritmo de firma será RSA  
        XMLSignature xmlSignature = new XMLSignature(doc ,baseURI, XMLSignature.ALGO_ID_SIGNATURE_RSA);  
  
        // Añadimos el nodo de la firma a la raiz antes de firmar.  
        // Observe que ambos elementos pueden ser mezclados en una forma con referencias separadas  
        doc.getDocumentElement().appendChild(xmlSignature.getElement());  
  
        // Creamos el objeto que mapea: Document/Reference  
        Transforms transforms = new Transforms(doc);  
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);  
          
        // Añadimos lo anterior Documento / Referencia  
        // ALGO_ID_DIGEST_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";  
        xmlSignature.addDocument("", transforms, Constants.ALGO_ID_DIGEST_SHA1);  
  
        // Añadimos el KeyInfo del certificado cuya clave privada usamos  
        X509Certificate cert = (X509Certificate) ks.getCertificate(PRIVATE_KEY_ALIAS);  
        xmlSignature.addKeyInfo(cert);  
        xmlSignature.addKeyInfo(cert.getPublicKey());  
          
          
        // Realizamos la firma  
        xmlSignature.sign(privateKey);  
          
        // Guardamos archivo de firma en disco  
        DomUtils.outputDocToFile(doc, signatureFile);  
    }  
}
