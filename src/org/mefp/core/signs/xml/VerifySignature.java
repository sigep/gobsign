/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.mefp.core.signs.xml;
import java.io.File;  
import java.io.FileInputStream;
import java.security.PublicKey;  
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;  
import org.apache.xml.security.keys.KeyInfo;  
import org.apache.xml.security.signature.XMLSignature;  
import org.w3c.dom.*;  
  
import javax.xml.parsers.*;  
/**
 *
 * @author dyugar
 */
public class VerifySignature {
    /** 
     * Punto de inicio 
     */  
    public static void main(String args[]) throws Exception {  
        org.apache.xml.security.Init.init();  
  
        String signatureFileName = "E:\\herramientas\\signaturexml.xml";  
  
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();  
  
        dbf.setNamespaceAware(true);  
        dbf.setAttribute("http://xml.org/sax/features/namespaces", Boolean.TRUE);
        //namespace
          
        File            f   = new File(signatureFileName);  
        DocumentBuilder db  = dbf.newDocumentBuilder();  
        Document     doc    = db.parse(new java.io.FileInputStream(f));  
        Element      sigElement = (Element) doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#","Signature").item(0);  
        //System.out.println(sigElement);
        XMLSignature signature  = new XMLSignature(sigElement, f.toURL().toString());  
  
        KeyInfo keyInfo = signature.getKeyInfo();  
        if (keyInfo != null) {  
            X509Certificate cert = keyInfo.getX509Certificate();  
            if (cert != null) {  
                // Validamos la firma usando un certificado X509  
                if (signature.checkSignatureValue(cert)){  
                    System.out.println("Válido según el certificado");    
                } else {  
                    System.out.println("Inválido según el certificado");      
                }  
                
                //validamos el certificado con su llave pública
                 try{
                    System.out.println("++++Verificación del Certificado++++++++");
                    PublicKey pk = cert.getPublicKey();
                    cert.verify(pk);//63
                    System.out.println("++Este certificado es válido++"); 
                    }
                 catch(CertificateException e){
                            e.printStackTrace();
                            System.out.println("El certificado es inválidos");
                 }
                
            } else {  
                // No encontramos un Certificado intentamos validar por la cláve pública  
                PublicKey pk = keyInfo.getPublicKey();  
                if (pk != null) {  
                    // Validamos usando la clave pública  
                    if (signature.checkSignatureValue(pk)){  
                        System.out.println("Válido según la clave pública");      
                    } else {  
                        System.out.println("Inválido según la clave pública");    
                    }  
                } else {  
                    System.out.println("No podemos validar, tampoco hay clave pública");  
                }  
            }  
        } else {  
            System.out.println("No ha sido posible encontrar el KeyInfo");  
        }  
    }  
}
